#!/usr/bin/perl

# Debug Monitor - task monitor of the Miniservers in a window of its own.
# Same full-screen trick as monitor.cgi ("nopanels"); the data comes from
# ajax.cgi?action=taskmon, filled by the receiver from the task monitor
# records in the debug stream.

use strict;
use warnings;
use CGI;
use JSON;
use HTML::Template;
use LoxBerry::System;
use LoxBerry::Web;

my $template = LoxBerry::System::read_file("$lbptemplatedir/taskmon.html");
my $templateout = HTML::Template->new_scalar_ref(
	\$template,
	global_vars       => 1,
	die_on_bad_params => 0,
);
my %L = LoxBerry::System::readlanguage( $templateout, 'language.ini' );

my %s = map { substr( $_, 5 ) => $L{$_} } grep { index( $_, 'TASK.' ) == 0 } keys %L;
my $json = JSON->new->canonical(1)->encode( \%s );
$json =~ s{</}{<\\/}g;
$templateout->param( TASK_STRINGS => $json );

LoxBerry::Web::lbheader( $L{'TASK.TITLE'}, 'nopanels', '', 'nojqm' );
print "<style>\n" . LoxBerry::System::read_file("$lbptemplatedir/style.css") . "</style>\n";
print $templateout->output();
LoxBerry::Web::lbfooter();
exit;
