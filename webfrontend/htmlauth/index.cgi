#!/usr/bin/perl

# Debug Monitor web interface.
#
# LoxBerry Design System (lb-* classes), not jQuery Mobile: the fourth argument
# to lbheader() is "nojqm". Four tabs, selected through ?form=. The tab bar is
# built by lbheader() from %navbar. Everything live comes from ajax.cgi.
# The full-screen monitor is a page of its own (monitor.cgi).

use strict;
use warnings;
use CGI;
use JSON;
use HTML::Template;
use LoxBerry::System;
use LoxBerry::Web;
use LoxBerry::Log;
use LoxBerry::Storage;
use lib $lbpbindir;
use DebugMonitor;

my $cgi = CGI->new;
my $q   = $cgi->Vars;

my $version = LoxBerry::System::pluginversion();
my $WIKI    = 'https://wiki.loxberry.de/plugins/debugmonitor/start';

my %TABS = ( start => 'tab_start.html', monitor => 'tab_monitor.html', ai => 'tab_ai.html', logs => 'tab_logfiles.html' );
$q->{form} = 'start' if ( !$q->{form} or !$TABS{ $q->{form} } );

my $template = LoxBerry::System::read_file("$lbptemplatedir/$TABS{ $q->{form} }");
$template .= LoxBerry::System::read_file("$lbptemplatedir/javascript.js") if ( $q->{form} ne 'logs' );

my $templateout = HTML::Template->new_scalar_ref(
	\$template,
	global_vars       => 1,
	loop_context_vars => 1,
	die_on_bad_params => 0,
);
my %L = LoxBerry::System::readlanguage( $templateout, 'language.ini' );

my $cfg = DebugMonitor::load_config();
$templateout->param(
	WIKI_URL   => $WIKI,
	FORM       => $q->{form},
	LBIP       => ( DebugMonitor::local_ip() // '' ),
	JS_STRINGS => js_strings( \%L, 'JS' ),
	MS_JSON    => js_json( $q->{form} eq 'start' ? DebugMonitor::miniservers() : [] ),
	CFG_JSON   => js_json( {
		%$cfg,
		default_recdir => DebugMonitor::default_recdir(),
	} ),
);

if ( $q->{form} eq 'start' ) {
	# The storage selection of the LoxBerry library: USB, network shares, local
	# and a custom path. It keeps the chosen path in the hidden field #recpath.
	my $html = LoxBerry::Storage::get_storage_html(
		formid      => 'recpath',
		currentpath => DebugMonitor::recdir($cfg),
		label       => $L{'START.REC_STORAGE'},
		type_usb    => 1,
		type_net    => 1,
		type_local  => 1,
		type_custom => 1,
		readwriteonly => 1,
		custom_folder => 1,
		show_browse   => 1,
	);
	$templateout->param( STORAGE_HTML => $html // '' );
}

if ( $q->{form} eq 'ai' ) {
	# SSH access to the MCP server: the path comes from the LoxBerry library
	my $host = DebugMonitor::local_ip() // 'loxberry';
	$templateout->param( MCP_SSH_CMD => "claude mcp add loxberry-plugin-debugmonitor -- ssh loxberry\@$host perl $lbpbindir/dmon_ctl.pl mcp-stdio" );
}

if ( $q->{form} eq 'logs' ) {
	# The log list of the LoxBerry library (sessions receiver, watchdog, webui).
	# With CUSTOM_LOGLEVELS=true in plugin.cfg it brings its own loglevel
	# selector - no second one here.
	my $list = eval { LoxBerry::Web::loglist_html( PACKAGE => $lbpplugindir ) };
	$templateout->param( LOGLIST => $list // '' );
}

our %navbar;
$navbar{10}{Name}   = $L{'COMMON.TAB_START'};
$navbar{10}{URL}    = 'index.cgi';
$navbar{10}{active} = 1 if ( $q->{form} eq 'start' );
$navbar{20}{Name}   = $L{'COMMON.TAB_MONITOR'};
$navbar{20}{URL}    = 'index.cgi?form=monitor';
$navbar{20}{active} = 1 if ( $q->{form} eq 'monitor' );
$navbar{30}{Name}   = $L{'COMMON.TAB_AI'};
$navbar{30}{URL}    = 'index.cgi?form=ai';
$navbar{30}{active} = 1 if ( $q->{form} eq 'ai' );
$navbar{40}{Name}   = $L{'COMMON.TAB_LOGS'};
$navbar{40}{URL}    = 'index.cgi?form=logs';
$navbar{40}{active} = 1 if ( $q->{form} eq 'logs' );

LoxBerry::Web::lbheader( $L{'COMMON.PLUGIN_TITLE'} . " V$version", $WIKI, '', 'nojqm' );
print LoxBerry::Log::get_notifications_html($lbpplugindir);
print "<style>\n" . LoxBerry::System::read_file("$lbptemplatedir/style.css") . "</style>\n";
print $templateout->output();
LoxBerry::Web::lbfooter();
exit;

# All keys of one language section as a JSON object for the browser
sub js_strings
{
	my ( $l, $section ) = @_;
	my %s = map { substr( $_, length($section) + 1 ) => $l->{$_} } grep { index( $_, "$section." ) == 0 } keys %$l;
	return js_json( \%s );
}

# JSON that is safe inside a <script> element
sub js_json
{
	my $j = JSON->new->canonical(1)->encode( $_[0] );
	$j =~ s{</}{<\\/}g;
	return $j;
}
