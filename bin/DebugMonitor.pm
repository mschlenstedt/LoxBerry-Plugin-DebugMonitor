package DebugMonitor;

# Shared logic of the Debug Monitor plugin: configuration, starting and
# stopping the receiver, status, port check, live lines and recordings.
# Used by ajax.cgi, index.cgi and dmon_ctl.pl (boot).
#
# The receiver (dmon_receiver.py) is the only process that touches the UDP
# port. Whether it should run is decided by a flag file in config/ (survives a
# reboot and an upgrade): Stop creates it, Start removes it. Boot and the
# watchdog (cron, every minute) only start the receiver while the flag is absent.

use strict;
use warnings;
use JSON;
use POSIX ();
use Fcntl qw(:flock SEEK_SET);
use Time::HiRes ();
use IO::Socket::INET;
use LoxBerry::System;

our $RECEIVER = 'dmon_receiver.py';
our $MCP      = 'dmon_mcp.py';
our $REC_RE   = qr/^dm_\d{8}_\d{6}(?:_crash)?\.raw\.gz$/;
# Task monitor figures, one file per Miniserver and month
our $CSV_RE   = qr/^taskmon_\d{1,3}(?:\.\d{1,3}){3}_\d{4}-\d{2}\.csv$/;
our $FILE_RE  = qr/(?:$REC_RE)|(?:$CSV_RE)/;

my %DEFAULTS = (
	port   => 7777,
	record => { enabled => 1, path => '', flush_min => 60, keep_mb => 1024, keep_days => 30, csv => 1, csv_min => 5 },
	forward => { enabled => 0, host => '', port => 7777 },
	# MCP server for AI assistants, own network only, Bearer token
	mcp     => { enabled => 0, port => 7780, token => '' },
);

##########################################################################
# Paths - all derived from the LoxBerry library, never written out
##########################################################################

sub rundir        { return "/dev/shm/$lbpplugindir"; }
sub cfgfile       { return "$lbpconfigdir/pluginconfig.json"; }
sub flagfile      { return "$lbpconfigdir/monitor_stopped"; }
sub pidfile       { return rundir() . '/receiver.pid'; }
sub statusfile    { return rundir() . '/status.json'; }
sub default_recdir { return "$lbpdatadir/recordings"; }
sub failfile      { return rundir() . '/watchdog_failures'; }
sub mcp_pidfile   { return rundir() . '/mcp.pid'; }
sub mcp_failfile  { return rundir() . '/mcp_failures'; }

# Watchdog: restart attempts in a row before it gives up until the next manual
# start, and how long the status may stand still before the receiver counts as hung
our $WD_MAX_FAILURES = 5;
our $WD_HANG_SEC     = 120;
our $WD_HEALTHY_SEC  = 600;

sub recdir
{
	my ($cfg) = @_;
	$cfg ||= load_config();
	return ( $cfg->{record}{path} ne '' ) ? $cfg->{record}{path} : default_recdir();
}

##########################################################################
# Configuration
##########################################################################

sub load_config
{
	my $c = {};
	if ( open( my $fh, '<', cfgfile() ) ) {
		local $/;
		my $raw = <$fh>;
		close $fh;
		eval { $c = JSON::from_json($raw); };
		$c = {} if ( $@ or ref($c) ne 'HASH' );
	}
	my %cfg = ( port => $c->{port} // $DEFAULTS{port} );
	foreach my $sect (qw(record forward mcp)) {
		my $in = ref( $c->{$sect} ) eq 'HASH' ? $c->{$sect} : {};
		$cfg{$sect} = { map { $_ => ( $in->{$_} // $DEFAULTS{$sect}{$_} ) } keys %{ $DEFAULTS{$sect} } };
	}
	return \%cfg;
}

sub _int_in
{
	my ( $v, $min, $max ) = @_;
	return undef if ( !defined $v or $v !~ /^\s*\d+\s*$/ );
	$v += 0;
	return ( $v >= $min and $v <= $max ) ? $v : undef;
}

sub is_local_host
{
	my ($host) = @_;
	return 1 if ( $host =~ /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0)$/i );
	my $ip = local_ip();
	return ( defined $ip and $host eq $ip ) ? 1 : 0;
}

# Takes what the interface sends, returns ( $cfg, undef ) or ( undef, $errorkey ).
# Error keys are translated in the browser.
sub validate
{
	my ($d) = @_;
	return ( undef, 'baddata' ) if ( ref($d) ne 'HASH' );
	my $cfg = load_config();

	if ( exists $d->{port} ) {
		my $p = _int_in( $d->{port}, 1024, 65535 );
		return ( undef, 'badport' ) if ( !defined $p );
		$cfg->{port} = $p;
	}
	if ( ref( $d->{record} ) eq 'HASH' ) {
		my $r = $d->{record};
		$cfg->{record}{enabled} = $r->{enabled} ? 1 : 0 if ( exists $r->{enabled} );
		if ( exists $r->{path} ) {
			my $path = $r->{path} // '';
			$path =~ s{/+$}{};
			return ( undef, 'badpath' ) if ( $path ne '' and ( $path !~ m{^/} or $path =~ m{(^|/)\.\.(/|$)} or $path =~ /[\0\n]/ ) );
			$cfg->{record}{path} = $path;
		}
		$cfg->{record}{csv} = $r->{csv} ? 1 : 0 if ( exists $r->{csv} );
		if ( exists $r->{csv_min} ) {
			my $v = _int_in( $r->{csv_min}, 1, 60 );
			return ( undef, 'bad_csv_min' ) if ( !defined $v );
			$cfg->{record}{csv_min} = $v;
		}
		foreach my $k ( [ 'flush_min', 5, 1440 ], [ 'keep_mb', 0, 10_000_000 ], [ 'keep_days', 0, 3650 ] ) {
			my ( $name, $min, $max ) = @$k;
			next if ( !exists $r->{$name} );
			my $v = _int_in( $r->{$name}, $min, $max );
			return ( undef, "bad_$name" ) if ( !defined $v );
			$cfg->{record}{$name} = $v;
		}
	}
	if ( ref( $d->{forward} ) eq 'HASH' ) {
		my $f = $d->{forward};
		$cfg->{forward}{enabled} = $f->{enabled} ? 1 : 0 if ( exists $f->{enabled} );
		if ( exists $f->{host} ) {
			my $h = $f->{host} // '';
			$h =~ s/^\s+|\s+$//g;
			return ( undef, 'badhost' ) if ( $h ne '' and ( length($h) > 253 or $h !~ /^[A-Za-z0-9.\-]+$/ ) );
			$cfg->{forward}{host} = $h;
		}
		if ( exists $f->{port} ) {
			my $p = _int_in( $f->{port}, 1, 65535 );
			return ( undef, 'badfwdport' ) if ( !defined $p );
			$cfg->{forward}{port} = $p;
		}
	}
	if ( $cfg->{forward}{enabled} ) {
		return ( undef, 'nohost' ) if ( $cfg->{forward}{host} eq '' );
		# Forwarding to ourselves would feed every datagram back in, forever
		return ( undef, 'fwdloop' )
			if ( $cfg->{forward}{port} == $cfg->{port} and is_local_host( $cfg->{forward}{host} ) );
	}
	return ( $cfg, undef );
}

sub save_config
{
	my ($cfg) = @_;
	my $file = cfgfile();
	my $tmp  = "$file.tmp";
	open( my $fh, '>', $tmp ) or return undef;
	print $fh JSON->new->pretty->canonical(1)->encode($cfg);
	close($fh) or return undef;
	rename( $tmp, $file ) or return undef;
	return 1;
}

##########################################################################
# Receiver process
##########################################################################

# PID of the running receiver of THIS plugin folder, or undef
sub receiver_pid
{
	my $pid = _read_pidfile();
	return undef if ( !$pid );
	return undef if ( !kill( 0, $pid ) );
	return _is_receiver($pid) ? $pid : undef;
}

sub _read_pidfile
{
	open( my $fh, '<', pidfile() ) or return undef;
	my $pid = <$fh>;
	close $fh;
	return ( defined $pid and $pid =~ /^(\d+)/ ) ? $1 : undef;
}

sub _is_receiver
{
	my ($pid) = @_;
	open( my $fh, '<', "/proc/$pid/cmdline" ) or return 0;
	local $/;
	my $cmd = <$fh> // '';
	close $fh;
	return index( $cmd, "$lbpbindir/$RECEIVER" ) >= 0 ? 1 : 0;
}

# Receivers started from this plugin folder, also without a PID file (orphans)
sub _all_receivers
{
	my @pids;
	opendir( my $dh, '/proc' ) or return ();
	foreach my $p ( readdir $dh ) {
		next if ( $p !~ /^\d+$/ );
		push @pids, $p if ( _is_receiver($p) );
	}
	closedir $dh;
	return @pids;
}

# Start, stop, boot and watchdog are serialised with a lock file on the tmpfs,
# so a watchdog run cannot start a receiver while the user stops it.
sub _ctl_lock
{
	my ($nonblocking) = @_;
	my $run = rundir();
	mkdir $run if ( !-d $run );
	open( my $fh, '>>', "$run/ctl.lock" ) or return undef;
	return flock( $fh, LOCK_EX | ( $nonblocking ? LOCK_NB : 0 ) ) ? $fh : undef;
}

# Manual start (web interface, command line): clears the stop flag and the
# watchdog's failure counter
sub start
{
	my $lock = _ctl_lock();
	return _start();
}

sub stop
{
	my %o    = @_;
	my $lock = _ctl_lock();
	return _stop(%o);
}

# Boot: start only if the user did not stop the monitor and it is not running
sub boot
{
	my $lock = _ctl_lock();
	_mcp_ensure();
	return { ok => 1, state => 'stopped' } if ( stopped_by_user() );
	my $pid = receiver_pid();
	return { ok => 1, state => 'running', pid => $pid } if ($pid);
	my $r = _start( auto => 1 );
	$r->{state} = 'started';
	return $r;
}

# Called by cron every minute. Silent while there is nothing to do; writes a
# log session only when it restarts the receiver.
sub watchdog
{
	my $result = _watchdog();
	# Trace of the last run on the tmpfs (no SD writes): what it decided and why
	if ( open( my $fh, '>', rundir() . '/watchdog_last' ) ) {
		print $fh POSIX::strftime( '%Y-%m-%d %H:%M:%S', localtime ) . " $result\n";
		close $fh;
	}
	return $result;
}

sub _watchdog
{
	# The MCP server follows its own switch, independent of the monitor's flag
	my $mcp_todo = _mcp_todo();
	if ( !$mcp_todo ) {
		return 'stopped' if ( stopped_by_user() );
		return 'running' if ( _healthy() );
	}

	# An install or update stops the receiver on purpose - hands off meanwhile.
	# Waits a little like the Smartmeter watchdog, so a short busy moment does
	# not cost a whole minute.
	my $busylock = "$lbpplugindir-watchdog";
	my $busy     = LoxBerry::System::lock( lockfile => $busylock, wait => 20 );
	return "busy (LoxBerry lock: $busy)" if ($busy);
	my $lock = _ctl_lock(1);
	my $result = 'busy (start or stop in progress)';
	if ($lock) {
		my $mcp = _mcp_todo() ? 'mcp ' . _mcp_watch_locked() . '; ' : '';
		$result = $mcp . _watchdog_locked();
	}
	undef $lock;
	LoxBerry::System::unlock( lockfile => $busylock );
	return $result;
}

sub _healthy
{
	my $pid = receiver_pid() or return 0;
	my $st  = read_status();
	# Status is rewritten every 2 s; a status that stands still means a hung receiver
	return 0 if ( $st and $st->{updated} and time() - $st->{updated} > $WD_HANG_SEC );
	unlink failfile() if ( $st and $st->{started} and time() - $st->{started} > $WD_HEALTHY_SEC and -e failfile() );
	return 1;
}

sub _watchdog_locked
{
	# Checked again under the lock: the user may have acted in the meantime
	return 'stopped' if ( stopped_by_user() );
	return 'running' if ( _healthy() );
	my $why = receiver_pid() ? "hangs (no status for more than $WD_HANG_SEC s)" : 'is not running';

	my $failures = _read_failures() + 1;
	_write_failures($failures);
	require LoxBerry::Log;
	if ( $failures > $WD_MAX_FAILURES ) {
		return 'gaveup' if ( $failures > $WD_MAX_FAILURES + 1 );
		my $log = _watchdog_log();
		$log->ERR("Debug Monitor $why. It failed $WD_MAX_FAILURES times in a row - "
			. 'no further restarts until it is started manually.');
		$log->LOGEND();
		return 'gaveup';
	}
	my $log = _watchdog_log();
	$log->ERR("Debug Monitor $why - restarting (attempt $failures of $WD_MAX_FAILURES).");
	my $r = _start( auto => 1 );
	if ( $r->{ok} ) {
		$log->OK("Debug Monitor restarted (PID $r->{pid}).");
	}
	else {
		$log->ERR( 'Restart failed' . ( $r->{detail} ? ": $r->{detail}" : '' ) . '. Details in the receiver log.' );
	}
	$log->LOGEND();
	return $r->{ok} ? 'restarted' : 'failed';
}

sub _watchdog_log
{
	my $log = LoxBerry::Log->new(
		name    => 'watchdog',
		package => $lbpplugindir,
		logdir  => $lbplogdir,
		addtime => 1,
	);
	$log->LOGSTART('Debug Monitor watchdog');
	return $log;
}

sub _read_failures
{
	open( my $fh, '<', failfile() ) or return 0;
	my $n = <$fh>;
	close $fh;
	return ( defined $n and $n =~ /^(\d+)/ ) ? $1 : 0;
}

sub _write_failures
{
	my ($n) = @_;
	open( my $fh, '>', failfile() ) or return;
	print $fh "$n\n";
	close $fh;
}

sub _start
{
	my %o = @_;
	_stop( keepflag => 1 );
	# A manual start is the user's "run it": clear the stop flag and give the
	# watchdog a fresh set of attempts. Boot and watchdog leave both alone.
	if ( !$o{auto} ) {
		unlink flagfile();
		unlink failfile();
	}
	my $run = rundir();
	mkdir $run if ( !-d $run );
	unlink statusfile();
	my $cfg = load_config();

	require LoxBerry::Log;
	my $log = LoxBerry::Log->new(
		name    => 'receiver',
		package => $lbpplugindir,
		logdir  => $lbplogdir,
		addtime => 1,
	);
	$log->LOGSTART('Debug Monitor receiver');
	$log->INF( "Port $cfg->{port}, recording " . ( $cfg->{record}{enabled} ? 'to ' . recdir($cfg) : 'off' )
		. ( $cfg->{forward}{enabled} ? ", forwarding to $cfg->{forward}{host}:$cfg->{forward}{port}" : '' ) );
	my $logfile  = $log->{filename};
	my $logdbkey = $log->{dbkey} // 0;
	my $loglevel = $log->loglevel // 6;
	# The receiver continues this session and closes it with LOGEND
	$log->{logend_called} = 1;
	undef $log;

	my @cmd = (
		'python3', "$lbpbindir/$RECEIVER",
		'--config',   cfgfile(),
		'--rundir',   $run,
		'--recdir',   default_recdir(),
		'--pidfile',  pidfile(),
		'--logfile',  $logfile,
		'--logdbkey', $logdbkey,
		'--loglevel', $loglevel,
	);

	return { ok => 0, error => 'startfailed' } if ( !_spawn( \@cmd, $logfile ) );

	# Wait until it listens (PID file) or gave up (status with an error)
	for ( 1 .. 50 ) {
		Time::HiRes::sleep(0.1);
		my $p = receiver_pid();
		return { ok => 1, pid => $p } if ($p);
		my $st = read_status();
		return { ok => 0, error => 'startfailed', detail => $st->{error} }
			if ( $st and !$st->{running} and $st->{error} );
	}
	return { ok => 0, error => 'startfailed' };
}

# Double fork + setsid: a process started from a CGI request must not die
# with it, and must not keep the web server's output pipe open.
sub _spawn
{
	my ( $cmd, $logfile ) = @_;
	my $pid = fork();
	return 0 if ( !defined $pid );
	if ( $pid == 0 ) {
		POSIX::setsid();
		my $pid2 = fork();
		POSIX::_exit(0) if ( !defined $pid2 or $pid2 );
		open( STDIN,  '<',  '/dev/null' );
		open( STDOUT, '>',  '/dev/null' );
		open( STDERR, '>>', $logfile ) or open( STDERR, '>', '/dev/null' );
		exec(@$cmd) or POSIX::_exit(127);
	}
	waitpid( $pid, 0 );
	return 1;
}

##########################################################################
# MCP server (dmon_mcp.py --http) - read access for AI assistants
##########################################################################

sub _is_mcp
{
	my ($pid) = @_;
	open( my $fh, '<', "/proc/$pid/cmdline" ) or return 0;
	local $/;
	my $cmd = <$fh> // '';
	close $fh;
	# Only the HTTP server; stdio sessions over SSH belong to their client
	return ( index( $cmd, "$lbpbindir/$MCP" ) >= 0 and index( $cmd, "--http" ) >= 0 ) ? 1 : 0;
}

sub mcp_pid
{
	open( my $fh, '<', mcp_pidfile() ) or return undef;
	my $pid = <$fh>;
	close $fh;
	return undef if ( !defined $pid or $pid !~ /^(\d+)/ );
	$pid = $1;
	return ( kill( 0, $pid ) and _is_mcp($pid) ) ? $pid : undef;
}

sub _all_mcp
{
	my @pids;
	opendir( my $dh, '/proc' ) or return ();
	push @pids, grep { /^\d+$/ and _is_mcp($_) } readdir $dh;
	closedir $dh;
	return @pids;
}

sub mcp_stop
{
	my @pids = _all_mcp();
	kill( 'TERM', @pids ) if (@pids);
	my $deadline = time() + 5;
	while ( @pids and time() < $deadline ) {
		Time::HiRes::sleep(0.1);
		@pids = grep { kill( 0, $_ ) and _is_mcp($_) } @pids;
	}
	kill( 'KILL', @pids ) if (@pids);
	unlink mcp_pidfile();
	return { ok => 1 };
}

sub mcp_start
{
	my %o = @_;
	mcp_stop();
	unlink mcp_failfile() if ( !$o{auto} );
	my $cfg = load_config();
	return { ok => 0, error => 'mcpnotoken' } if ( !$cfg->{mcp}{token} );
	my $run = rundir();
	mkdir $run if ( !-d $run );

	require LoxBerry::Log;
	my $log = LoxBerry::Log->new(
		name    => 'mcp',
		package => $lbpplugindir,
		logdir  => $lbplogdir,
		addtime => 1,
	);
	$log->LOGSTART('Debug Monitor MCP server');
	my $logfile  = $log->{filename};
	my $logdbkey = $log->{dbkey} // 0;
	my $loglevel = $log->loglevel // 6;
	$log->{logend_called} = 1;
	undef $log;

	my @cmd = (
		'python3', "$lbpbindir/$MCP", '--http',
		'--port',     $cfg->{mcp}{port},
		'--config',   cfgfile(),
		'--rundir',   $run,
		'--recdir',   default_recdir(),
		'--pidfile',  mcp_pidfile(),
		'--version',  ( LoxBerry::System::pluginversion() // '' ),
		'--logfile',  $logfile,
		'--logdbkey', $logdbkey,
		'--loglevel', $loglevel,
	);
	return { ok => 0, error => 'mcpstartfailed' } if ( !_spawn( \@cmd, $logfile ) );
	for ( 1 .. 50 ) {
		Time::HiRes::sleep(0.1);
		my $p = mcp_pid();
		return { ok => 1, pid => $p } if ($p);
	}
	return { ok => 0, error => 'mcpstartfailed' };
}

# What the switch in the settings asks for: '' (nothing to do), 'start',
# 'restart' (process alive, but no answer) or 'stop'
sub _mcp_todo
{
	my $cfg = load_config();
	my $pid = mcp_pid();
	return 'stop' if ( !$cfg->{mcp}{enabled} and $pid );
	return '' if ( !$cfg->{mcp}{enabled} or _read_n( mcp_failfile() ) > $WD_MAX_FAILURES );
	return 'start' if ( !$pid );
	return _mcp_responds( $cfg->{mcp}{port} ) ? '' : 'restart';
}

# A hung server keeps its process: ask it on its own port. GET / needs no
# token and answers at once; a running tool call does not block it (threads).
sub _mcp_responds
{
	my ($port) = @_;
	my $s = IO::Socket::INET->new( PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 5 )
		or return 0;
	print $s "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
	require IO::Select;
	my $line = IO::Select->new($s)->can_read(10) ? <$s> : undef;
	close $s;
	return ( defined $line and $line =~ m{^HTTP/1\.\d 200} ) ? 1 : 0;
}

# Boot and settings: bring the MCP server in line with its switch
sub _mcp_ensure
{
	my $todo = _mcp_todo();
	return 'ok' if ( !$todo );
	if ( $todo eq 'stop' ) { mcp_stop(); return 'stopped'; }
	my $r = mcp_start( auto => 1 );
	return $r->{ok} ? 'started' : 'failed';
}

sub _mcp_watch_locked
{
	my $todo = _mcp_todo();
	return 'ok' if ( !$todo );
	if ( $todo eq 'stop' ) { mcp_stop(); return 'stopped'; }
	my $failures = _read_n( mcp_failfile() ) + 1;
	_write_n( mcp_failfile(), $failures );
	require LoxBerry::Log;
	my $log = _watchdog_log();
	my $why = $todo eq 'restart' ? 'does not answer' : 'is not running';
	$log->ERR("MCP server $why - starting it (attempt $failures of $WD_MAX_FAILURES).");
	my $r = mcp_start( auto => 1 );
	if ( $r->{ok} ) { $log->OK("MCP server started (PID $r->{pid})."); unlink mcp_failfile(); }
	else           { $log->ERR('MCP server could not be started. Details in the MCP log.'); }
	$log->LOGEND();
	return $r->{ok} ? 'started' : 'failed';
}

sub _read_n
{
	my ($file) = @_;
	open( my $fh, '<', $file ) or return 0;
	my $n = <$fh>;
	close $fh;
	return ( defined $n and $n =~ /^(\d+)/ ) ? $1 : 0;
}

sub _write_n
{
	my ( $file, $n ) = @_;
	open( my $fh, '>', $file ) or return;
	print $fh "$n\n";
	close $fh;
}

# SSH access: "ssh loxberry@<host> perl <bindir>/dmon_ctl.pl mcp-stdio"
sub mcp_stdio_exec
{
	exec( 'python3', "$lbpbindir/$MCP", '--stdio',
		'--config',  cfgfile(),
		'--rundir',  rundir(),
		'--recdir',  default_recdir(),
		'--version', ( LoxBerry::System::pluginversion() // '' ) );
	die "Cannot start $MCP: $!\n";
}

sub new_token
{
	open( my $fh, '<', '/dev/urandom' ) or return undef;
	my $raw;
	read( $fh, $raw, 24 );
	close $fh;
	return unpack( 'H*', $raw );
}

# TCP port for the MCP server: free | own | used | invalid
sub tcp_port_check
{
	my ($port) = @_;
	return 'invalid' if ( !defined _int_in( $port, 1024, 65535 ) );
	return 'own' if ( mcp_pid() and load_config()->{mcp}{port} == $port );
	my $s = IO::Socket::INET->new( Proto => 'tcp', LocalAddr => '0.0.0.0', LocalPort => $port, Listen => 1, ReuseAddr => 1 );
	return 'used' if ( !$s );
	close $s;
	return 'free';
}

sub _stop
{
	my %o = @_;
	my @pids = _all_receivers();
	kill( 'TERM', @pids ) if (@pids);
	# The receiver saves the current recording before it exits - on a slow
	# network share this takes a moment.
	my $deadline = time() + 30;
	while ( @pids and time() < $deadline ) {
		Time::HiRes::sleep(0.2);
		@pids = grep { kill( 0, $_ ) and _is_receiver($_) } @pids;
	}
	kill( 'KILL', @pids ) if (@pids);
	unlink pidfile();
	if ( !$o{keepflag} and open( my $fh, '>', flagfile() ) ) {
		close $fh;
	}
	return { ok => 1, killed => scalar(@pids) };
}

sub stopped_by_user { return -e flagfile() ? 1 : 0; }

sub read_status
{
	open( my $fh, '<', statusfile() ) or return undef;
	local $/;
	my $raw = <$fh>;
	close $fh;
	my $st;
	eval { $st = JSON::from_json($raw); };
	return ( !$@ and ref($st) eq 'HASH' ) ? $st : undef;
}

sub status
{
	my $pid = receiver_pid();
	my $st  = read_status() || {};
	$st->{running} = $pid ? 1 : 0;
	$st->{pid}     = $pid;
	my $fails = _read_failures();
	return {
		running  => $pid ? 1 : 0,
		stopped  => stopped_by_user(),
		receiver => $st,
		watchdog => { failures => $fails, gaveup => $fails > $WD_MAX_FAILURES ? 1 : 0 },
		mcp      => { running => mcp_pid() ? 1 : 0, failures => _read_n( mcp_failfile() ) },
		now      => Time::HiRes::time(),
	};
}

##########################################################################
# Port check and own address
##########################################################################

# free | own (our receiver listens there) | used | invalid
sub port_check
{
	my ($port) = @_;
	return 'invalid' if ( !defined _int_in( $port, 1024, 65535 ) );
	if ( receiver_pid() ) {
		my $st = read_status();
		return 'own' if ( $st and ( $st->{port} // 0 ) == $port );
	}
	my $s = IO::Socket::INET->new( Proto => 'udp', LocalAddr => '0.0.0.0', LocalPort => $port );
	return 'used' if ( !$s );
	close $s;
	return 'free';
}

sub local_ip
{
	my $ip = eval { LoxBerry::System::get_localip() };
	return $ip if ( $ip and $ip ne '0.0.0.0' );
	my $all = qx(hostname -I 2>/dev/null) // '';
	return ( $all =~ /(\d+\.\d+\.\d+\.\d+)/ ) ? $1 : undef;
}

##########################################################################
# Live lines for the monitor
##########################################################################

# Position "inode:offset" in live.jsonl. Returns the JSON lines since then, at
# most $max bytes and always whole lines. Without a position: the last lines.
sub live
{
	my ( $pos, $max ) = @_;
	$max ||= 256 * 1024;
	my $cur = rundir() . '/live.jsonl';
	my $old = rundir() . '/live.1.jsonl';
	my ( $cino, $csize ) = ( stat $cur )[ 1, 7 ];
	my ( $oino, $osize ) = ( stat $old )[ 1, 7 ];
	$cino //= 0; $csize //= 0; $oino //= 0; $osize //= 0;

	my ( $ino, $off ) = ( defined $pos and $pos =~ /^(\d+):(\d+)$/ ) ? ( $1, $2 ) : ( undef, undef );

	if ( defined $ino and $ino == $cino and $cino and $off <= $csize ) {
		my $d = _read_lines( $cur, $off, $max );
		return { data => $d, pos => "$cino:" . ( $off + length $d ), more => ( $off + length($d) < $csize ? 1 : 0 ) };
	}
	if ( defined $ino and $ino == $oino and $oino and $off <= $osize ) {
		# The file was rotated since the last call: rest of the old one first
		my $d = _read_lines( $old, $off, $max );
		if ( $off + length($d) < $osize ) {
			return { data => $d, pos => "$oino:" . ( $off + length $d ), more => 1 };
		}
		# Between the rename and the next write there is no current file yet:
		# stay at the end of the old one instead of losing track
		return { data => $d, pos => "$oino:$osize", more => 0 } if ( !$cino );
		my $d2 = $cino ? _read_lines( $cur, 0, $max - length($d) ) : '';
		return { data => $d . $d2, pos => "$cino:" . length($d2), more => ( length($d2) < $csize ? 1 : 0 ) };
	}
	# First call or lost track: the tail, across both files if needed
	my $tail = 96 * 1024;
	my $data = '';
	if ( $csize < $tail and $oino ) {
		my $from = $osize - ( $tail - $csize );
		$from = 0 if ( $from < 0 );
		$data = _read_lines( $old, $from, $tail, 1 );
	}
	return { data => $data, pos => "$oino:$osize", more => 0 } if ( !$cino );
	my $from = $csize - $tail;
	$from = 0 if ( $from < 0 );
	my $d = _read_lines( $cur, $from, $tail, $from > 0 );
	return { data => $data . $d, pos => "$cino:" . ( $from + length($d) + ( $from > 0 ? _skipped( $cur, $from ) : 0 ) ), more => 0 };
}

# Bytes skipped at $from to reach the next line start (for a tail read)
sub _skipped
{
	my ( $file, $from ) = @_;
	open( my $fh, '<:raw', $file ) or return 0;
	seek( $fh, $from, SEEK_SET );
	my $l = <$fh>;
	close $fh;
	return defined $l ? length $l : 0;
}

sub _read_lines
{
	my ( $file, $off, $max, $skip_partial ) = @_;
	return '' if ( $max <= 0 );
	open( my $fh, '<:raw', $file ) or return '';
	seek( $fh, $off, SEEK_SET );
	<$fh> if ($skip_partial);
	my $buf = '';
	read( $fh, $buf, $max );
	close $fh;
	my $nl = rindex( $buf, "\n" );
	return $nl >= 0 ? substr( $buf, 0, $nl + 1 ) : '';
}

##########################################################################
# Recordings
##########################################################################

sub recordings
{
	my $cfg = load_config();
	my $dir = recdir($cfg);
	my @list;
	my $total = 0;
	if ( opendir( my $dh, $dir ) ) {
		# Recordings first (newest first), then the CSV files
		my @names = grep { $_ =~ $FILE_RE } readdir $dh;
		foreach my $f ( ( sort { $b cmp $a } grep { $_ =~ $REC_RE } @names ), ( sort { $b cmp $a } grep { $_ =~ $CSV_RE } @names ) ) {
			my @s = stat "$dir/$f";
			next if ( !@s );
			push @list, { name => $f, size => $s[7], mtime => $s[9], csv => ( $f =~ $CSV_RE ? 1 : 0 ) };
			$total += $s[7];
		}
		closedir $dh;
	}
	return {
		dir        => $dir,
		exists     => ( -d $dir ? 1 : 0 ),
		writable   => ( -w $dir ? 1 : 0 ),
		files      => \@list,
		total      => $total,
		free_bytes => free_bytes($dir),
	};
}

sub free_bytes
{
	my ($dir) = @_;
	# The directory may not exist yet: ask for the nearest existing parent
	$dir =~ s{/[^/]+$}{} while ( $dir ne '' and !-d $dir );
	return undef if ( $dir eq '' );
	my $out = qx(df -Pk -- \Q$dir\E 2>/dev/null);
	my @l   = split /\n/, $out;
	return undef if ( @l < 2 );
	my @f = split /\s+/, $l[-1];
	return defined $f[3] ? $f[3] * 1024 : undef;
}

# Full path of a recording, only if the name is one of ours
sub recording_file
{
	my ($name) = @_;
	return undef if ( !defined $name or $name !~ $FILE_RE );
	my $f = recdir() . "/$name";
	return -f $f ? $f : undef;
}

sub delete_recording
{
	my ($name) = @_;
	my $f = recording_file($name);
	return { ok => 0, error => 'badfile' } if ( !$f );
	return unlink($f) ? { ok => 1 } : { ok => 0, error => 'deletefailed' };
}

# All recordings and CSV files on the storage - only our own name patterns
sub delete_all_recordings
{
	my $dir = recdir();
	my ( $deleted, $failed ) = ( 0, 0 );
	opendir( my $dh, $dir ) or return { ok => 1, deleted => 0, failed => 0 };
	foreach my $f ( grep { $_ =~ $FILE_RE } readdir $dh ) {
		unlink("$dir/$f") ? $deleted++ : $failed++;
	}
	closedir $dh;
	return { ok => ( $failed ? 0 : 1 ), deleted => $deleted, failed => $failed,
		( $failed ? ( error => 'deletefailed' ) : () ) };
}

# Decodes a recording into readable lines, written to $out (a filehandle)
sub write_text
{
	my ( $file, $out ) = @_;
	require IO::Uncompress::Gunzip;
	my $z = IO::Uncompress::Gunzip->new( $file, MultiStream => 1 ) or return 0;
	my $head;
	while ( $z->read( $head, 12 ) == 12 ) {
		my ( $ts, $len ) = unpack( 'd> N', $head );
		my $data = '';
		last if ( $z->read( $data, $len ) != $len );
		print $out decode_line( $data, $ts ), "\n";
	}
	$z->close;
	return 1;
}

# Same decoding as the receiver: header time (Miniserver local time) if valid
sub decode_line
{
	my ( $data, $ts ) = @_;
	if ( length($data) >= 29 and substr( $data, 0, 2 ) eq "\x1f\xfa" ) {
		my ( $ms, $secs ) = unpack( 'v V', substr( $data, 10, 6 ) );
		my $ip   = join( '.', unpack( 'C4', substr( $data, 16, 4 ) ) );
		# Bytes 6-7: kind of record, 0 = text message (see dmon_receiver.py)
		my $kind = unpack( 'v', substr( $data, 6, 2 ) );
		my $text = $kind == 0 ? substr( $data, 29 ) : substr( $data, 28 );
		if ( $kind == 0 ) {
			$text =~ s/\0.*//s;
			$text =~ s/[\r\n]+$//;
			# Some messages carry line breaks inside; one datagram stays one line
			$text =~ s/\r/\\r/g;
			$text =~ s/\n/\\n/g;
		}
		else {
			# Binary record (e.g. the task monitor): complete as hex
			$text =~ s/\x1f\x1f$//;
			$text = sprintf( '[%04x, %d B] ', $kind, length $text ) . join( ' ', unpack( '(H2)*', $text ) );
		}
		my $t;
		if ( $ms < 1000 ) {
			# Seconds since 2009-01-01 in the Miniserver's local time: format as UTC
			# from that epoch, which leaves the wall clock untouched
			$t = POSIX::strftime( '%Y-%m-%d %H:%M:%S', gmtime( 1230768000 + $secs ) ) . sprintf( '.%03d', $ms );
		}
		else {
			$t = _fmt_local($ts);
		}
		return "$t $ip $text";
	}
	return _fmt_local($ts) . ' [raw ' . length($data) . ' B] ' . join( ' ', unpack( '(H2)*', substr( $data, 0, 96 ) ) );
}

sub _fmt_local
{
	my ($ts) = @_;
	return POSIX::strftime( '%Y-%m-%d %H:%M:%S', localtime( int $ts ) ) . sprintf( '.%03d', ( $ts - int $ts ) * 1000 );
}

1;
