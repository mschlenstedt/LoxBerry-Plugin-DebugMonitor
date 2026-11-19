#!/usr/bin/perl

# Command line control of the Debug Monitor receiver. Runs as loxberry.
#
#   dmon_ctl.pl boot      start unless the user stopped the monitor (daemon.sh)
#   dmon_ctl.pl start     start (clears the stop flag)
#   dmon_ctl.pl stop      stop (sets the stop flag)
#   dmon_ctl.pl watchdog  restart a crashed or hung receiver unless the user
#                         stopped it (cron, every minute; silent if all is well)
#   dmon_ctl.pl status    print the status as JSON
#   dmon_ctl.pl mcp-stdio MCP server on stdin/stdout, for AI clients over SSH:
#                         ssh loxberry@<host> perl <this file> mcp-stdio
#   dmon_ctl.pl mcp-start / mcp-stop   the MCP server on its TCP port

use strict;
use warnings;
use JSON;
use LoxBerry::System;
use lib $lbpbindir;
use DebugMonitor;

my $cmd = $ARGV[0] // '';

if ( $cmd eq 'boot' ) {
	my $r = DebugMonitor::boot();
	print $r->{state} eq 'stopped' ? "Debug Monitor was stopped by the user - not started.\n"
	    : $r->{state} eq 'running' ? "Debug Monitor is already running.\n"
	    : $r->{ok}                 ? "Debug Monitor started (PID $r->{pid}).\n"
	    : "Debug Monitor could not be started" . ( $r->{detail} ? ": $r->{detail}" : '' ) . ".\n";
	exit( $r->{ok} ? 0 : 1 );
}
if ( $cmd eq 'watchdog' ) {
	print DebugMonitor::watchdog(), "\n";
	exit 0;
}

if ( $cmd eq 'start' ) {
	my $r = DebugMonitor::start();
	print $r->{ok} ? "Debug Monitor started (PID $r->{pid}).\n"
	               : "Debug Monitor could not be started" . ( $r->{detail} ? ": $r->{detail}" : '' ) . ".\n";
	exit( $r->{ok} ? 0 : 1 );
}
if ( $cmd eq 'stop' ) {
	DebugMonitor::stop();
	print "Debug Monitor stopped.\n";
	exit 0;
}
if ( $cmd eq 'mcp-stdio' ) {
	DebugMonitor::mcp_stdio_exec();
}
if ( $cmd eq 'mcp-start' ) {
	my $r = DebugMonitor::mcp_start();
	print $r->{ok} ? "MCP server started (PID $r->{pid}).\n" : "MCP server could not be started ($r->{error}).\n";
	exit( $r->{ok} ? 0 : 1 );
}
if ( $cmd eq 'mcp-stop' ) {
	DebugMonitor::mcp_stop();
	print "MCP server stopped.\n";
	exit 0;
}
if ( $cmd eq 'status' ) {
	print JSON->new->pretty->canonical(1)->encode( DebugMonitor::status() );
	exit 0;
}

print "Usage: $0 boot|start|stop|watchdog|status|mcp-start|mcp-stop|mcp-stdio\n";
exit 2;
