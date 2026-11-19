#!/usr/bin/perl

# Full-screen Debug Monitor. Opened by the "Debug Monitor" tab in a window of
# its own.
#
# lbheader() with "nopanels" as help URL renders the page without the side
# panels (pagestart_nopanels.html). No %navbar, so there is no tab bar either.
# The terminal itself is a fixed layer over the whole viewport, so the slim
# title row and the footer of the page frame stay hidden behind it.

use strict;
use warnings;
use CGI;
use JSON;
use HTML::Template;
use LoxBerry::System;
use LoxBerry::Web;

my $template = LoxBerry::System::read_file("$lbptemplatedir/monitor.html");
my $templateout = HTML::Template->new_scalar_ref(
	\$template,
	global_vars       => 1,
	die_on_bad_params => 0,
);
my %L = LoxBerry::System::readlanguage( $templateout, 'language.ini' );

my %s = map { substr( $_, 5 ) => $L{$_} } grep { index( $_, 'TERM.' ) == 0 } keys %L;
my $json = JSON->new->canonical(1)->encode( \%s );
$json =~ s{</}{<\\/}g;
$templateout->param( TERM_STRINGS => $json );

LoxBerry::Web::lbheader( $L{'COMMON.TAB_MONITOR'}, 'nopanels', '', 'nojqm' );
print "<style>\n" . LoxBerry::System::read_file("$lbptemplatedir/style.css") . "</style>\n";
print $templateout->output();
LoxBerry::Web::lbfooter();
exit;
