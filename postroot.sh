#!/bin/sh

# Runs as root, as the LAST of the lifecycle scripts. Creates the directories,
# fixes ownership and makes the scripts executable.
#
# Arguments: <TEMPFOLDER> <NAME> <FOLDER> <VERSION> <BASEFOLDER>

ARGV3=$3
ARGV5=$5

BINDIR="$ARGV5/bin/plugins/$ARGV3"
DATADIR="$ARGV5/data/plugins/$ARGV3"
CONFIGDIR="$ARGV5/config/plugins/$ARGV3"
LOGDIR="$ARGV5/log/plugins/$ARGV3"
HTMLAUTHDIR="$ARGV5/webfrontend/htmlauth/plugins/$ARGV3"

if [ "$(id -u)" != "0" ]; then
	echo "<ERROR> postroot.sh must run as root."
	exit 2
fi

for file in dmon_ctl.pl dmon_receiver.py dmon_mcp.py; do
	[ -e "$BINDIR/$file" ] && chmod +x "$BINDIR/$file"
done
for file in index.cgi ajax.cgi monitor.cgi taskmon.cgi; do
	[ -e "$HTMLAUTHDIR/$file" ] && chmod +x "$HTMLAUTHDIR/$file"
done

mkdir -p "$DATADIR/recordings" "$CONFIGDIR" "$LOGDIR"
chown -R loxberry:loxberry "$DATADIR" "$CONFIGDIR" "$LOGDIR"

# A new installation starts with the monitor stopped: it only receives once the
# user has chosen the port and pressed "Start". An upgrade keeps the state
# (the flag file is part of config/ and restored by postupgrade.sh).
if [ ! -e "$CONFIGDIR/.installed" ]; then
	[ -e "$CONFIGDIR/monitor_stopped" ] || touch "$CONFIGDIR/monitor_stopped"
	touch "$CONFIGDIR/.installed"
	chown loxberry:loxberry "$CONFIGDIR/monitor_stopped" "$CONFIGDIR/.installed"
fi

# Start again after an upgrade, unless the user had stopped the monitor
if [ -x "$BINDIR/dmon_ctl.pl" ]; then
	su loxberry --preserve-environment -s /bin/sh -c "\"$BINDIR/dmon_ctl.pl\" boot" </dev/null >/dev/null 2>&1 &
fi

echo "<OK> Debug Monitor installed."
exit 0
