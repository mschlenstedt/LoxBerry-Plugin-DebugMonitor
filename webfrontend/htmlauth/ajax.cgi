#!/usr/bin/perl

# AJAX endpoint of the web interface. Answers JSON, except for downloads.
#
# Errors come back as KEYS, not sentences: the browser owns the language.
# Anything that changes something needs POST.

use strict;
use warnings;
use CGI;
use JSON;
use LoxBerry::System;
# LoxBerry::System fills $lbpbindir from our own path, so this finds the
# plugin module without knowing the folder name.
use lib $lbpbindir;
use DebugMonitor;

my $cgi    = CGI->new;
my $q      = $cgi->Vars;
# On a POST, CGI.pm parses only the body - the action is in the URL
my $action = $q->{action} // $cgi->url_param('action') // '';

sub out
{
	print "Content-Type: application/json; charset=utf-8\nCache-Control: no-store\n\n";
	print JSON->new->canonical(1)->encode( $_[0] );
	exit 0;
}
sub err { out( { ok => 0, error => $_[0], ( $_[1] ? ( detail => $_[1] ) : () ) } ); }
sub is_post { return ( ( $ENV{REQUEST_METHOD} // '' ) eq 'POST' ); }

sub weblog
{
	my ($title) = @_;
	require LoxBerry::Log;
	my $l = LoxBerry::Log->new(
		name    => 'webui',
		package => $lbpplugindir,
		logdir  => $lbplogdir,
		addtime => 1,
	);
	$l->LOGSTART($title);
	return $l;
}

##########################################################################
# Reading
##########################################################################

if ( $action eq 'status' ) {
	my $s = DebugMonitor::status();
	$s->{ok} = 1;
	out($s);
}

# Task monitor of every Miniserver, as the receiver keeps it in RAM
if ( $action eq 'taskmon' ) {
	my $data = {};
	if ( open( my $fh, '<', DebugMonitor::rundir() . '/taskmon.json' ) ) {
		local $/;
		my $raw = <$fh>;
		close $fh;
		eval { $data = JSON::from_json($raw); };
		$data = {} if ( $@ or ref($data) ne 'HASH' );
	}
	out( { ok => 1, running => ( DebugMonitor::receiver_pid() ? 1 : 0 ), data => $data } );
}

if ( $action eq 'mcpportcheck' ) {
	out( { ok => 1, result => DebugMonitor::tcp_port_check( $q->{port} ) } );
}

if ( $action eq 'portcheck' ) {
	out( { ok => 1, port => $q->{port}, result => DebugMonitor::port_check( $q->{port} ) } );
}

if ( $action eq 'live' ) {
	my $r = DebugMonitor::live( $q->{pos} );
	$r->{ok}      = 1;
	$r->{running} = DebugMonitor::receiver_pid() ? 1 : 0;
	out($r);
}

if ( $action eq 'recordings' ) {
	my $r = DebugMonitor::recordings();
	$r->{ok} = 1;
	out($r);
}

# Download of a recording: raw (as stored) or decoded to text
if ( $action eq 'download' ) {
	my $file = DebugMonitor::recording_file( $q->{file} );
	err('badfile') if ( !$file );
	( my $base = $q->{file} ) =~ s/\.raw\.gz$//;
	binmode STDOUT;
	if ( $q->{file} =~ /\.csv$/ ) {
		print "Content-Type: text/csv; charset=utf-8\n";
		print "Content-Disposition: attachment; filename=\"$q->{file}\"\n\n";
		open( my $fh, '<:raw', $file ) or exit 0;
		my $buf;
		print $buf while ( read( $fh, $buf, 65536 ) );
		close $fh;
		exit 0;
	}
	if ( ( $q->{fmt} // '' ) eq 'raw' ) {
		print "Content-Type: application/gzip\n";
		print "Content-Disposition: attachment; filename=\"$base.raw.gz\"\n\n";
		open( my $fh, '<:raw', $file ) or exit 0;
		my $buf;
		print $buf while ( read( $fh, $buf, 65536 ) );
		close $fh;
		exit 0;
	}
	print "Content-Type: text/plain; charset=utf-8\n";
	print "Content-Disposition: attachment; filename=\"$base.txt\"\n\n";
	DebugMonitor::write_text( $file, \*STDOUT );
	exit 0;
}

##########################################################################
# Writing
##########################################################################

err('postrequired') if ( !is_post() );

if ( $action eq 'save' ) {
	my $data;
	eval { $data = JSON::from_json( $q->{data} // '' ); };
	err('baddata') if ( $@ or ref($data) ne 'HASH' );
	my ( $cfg, $e ) = DebugMonitor::validate($data);
	err($e) if ($e);

	# A changed port must be free - unless our own receiver holds the old one
	my $old = DebugMonitor::load_config();
	if ( $cfg->{port} != $old->{port} ) {
		my $pc = DebugMonitor::port_check( $cfg->{port} );
		err('portused') if ( $pc eq 'used' );
	}
	# The default storage is kept as "" so it follows the plugin folder
	$cfg->{record}{path} = '' if ( $cfg->{record}{path} eq DebugMonitor::default_recdir() );

	err('savefailed') if ( !DebugMonitor::save_config($cfg) );
	my $l = weblog('Settings saved');
	# The MCP token does not belong into a log file
	my %shown = ( %$cfg, mcp => { %{ $cfg->{mcp} }, token => ( $cfg->{mcp}{token} ? '***' : '' ) } );
	$l->INF( 'New settings: ' . JSON->new->canonical(1)->encode( \%shown ) );

	# A running receiver reads its settings at the start only
	my $restarted = 0;
	if ( DebugMonitor::receiver_pid() ) {
		my $r = DebugMonitor::start();
		$restarted = 1;
		if ( !$r->{ok} ) {
			$l->ERR( 'Restart failed' . ( $r->{detail} ? ": $r->{detail}" : '' ) );
			$l->LOGEND('failed');
			err( 'startfailed', $r->{detail} );
		}
	}
	$l->LOGEND('done');
	out( { ok => 1, restarted => $restarted, config => $cfg } );
}

if ( $action eq 'start' ) {
	my $cfg = DebugMonitor::load_config();
	if ( !DebugMonitor::receiver_pid() and DebugMonitor::port_check( $cfg->{port} ) eq 'used' ) {
		err('portused');
	}
	my $r = DebugMonitor::start();
	err( 'startfailed', $r->{detail} ) if ( !$r->{ok} );
	out( { ok => 1, pid => $r->{pid} } );
}

if ( $action eq 'stop' ) {
	out( DebugMonitor::stop() );
}

# MCP server: switch and port. Enabling creates a token if there is none yet.
if ( $action eq 'mcpsave' ) {
	my $cfg = DebugMonitor::load_config();
	my $on  = $q->{enabled} ? 1 : 0;
	my $port = DebugMonitor::_int_in( $q->{port}, 1024, 65535 );
	err('badmcpport') if ( !defined $port );
	if ( $on and DebugMonitor::tcp_port_check($port) eq 'used' ) {
		err('mcpportused');
	}
	$cfg->{mcp}{enabled} = $on;
	$cfg->{mcp}{port}    = $port;
	$cfg->{mcp}{token} ||= DebugMonitor::new_token() // '';
	err('savefailed') if ( !DebugMonitor::save_config($cfg) );
	my $l = weblog('MCP settings saved');
	$l->INF( 'MCP server ' . ( $on ? "on, TCP port $port" : 'off' ) );
	my $r = { ok => 1 };
	if ($on) {
		$r = DebugMonitor::mcp_start();
		$l->ERR('MCP server could not be started') if ( !$r->{ok} );
	}
	else {
		DebugMonitor::mcp_stop();
	}
	$l->LOGEND('done');
	err( $r->{error} ) if ( !$r->{ok} );
	out( { ok => 1, mcp => DebugMonitor::status()->{mcp}, token => $cfg->{mcp}{token} } );
}

if ( $action eq 'mcptoken' ) {
	my $cfg = DebugMonitor::load_config();
	$cfg->{mcp}{token} = DebugMonitor::new_token() // err('savefailed');
	err('savefailed') if ( !DebugMonitor::save_config($cfg) );
	my $l = weblog('MCP token renewed');
	$l->INF('New MCP access token created, the old one is no longer valid');
	$l->LOGEND('done');
	DebugMonitor::mcp_start() if ( DebugMonitor::mcp_pid() );
	out( { ok => 1, token => $cfg->{mcp}{token} } );
}

if ( $action eq 'deleteall' ) {
	my $r = DebugMonitor::delete_all_recordings();
	my $l = weblog('All recordings deleted');
	$l->INF("Deleted $r->{deleted} recordings" . ( $r->{failed} ? ", $r->{failed} could not be deleted" : '' ));
	$l->ERR("$r->{failed} recordings could not be deleted") if ( $r->{failed} );
	$l->LOGEND('done');
	out($r);
}

if ( $action eq 'deleterec' ) {
	my $r = DebugMonitor::delete_recording( $q->{file} );
	if ( $r->{ok} ) {
		my $l = weblog('Recording deleted');
		$l->INF("Deleted $q->{file}");
		$l->LOGEND('done');
	}
	out($r);
}

err('unknownaction');
