#!/bin/bash
# Runs BEFORE purge_installation() deletes config/ and data/ of this plugin.
# Stops the receiver (it saves its current recording on the way out), then moves
# config/ and data/ aside into sibling directories, which the purge does not
# touch. mv, not cp: recordings can be large.
#
# Arguments: <TEMPFOLDER> <NAME> <FOLDER> <VERSION> <BASEFOLDER> <TEMPDIR>

ARGV3=$3
ARGV5=$5

CTL="$ARGV5/bin/plugins/$ARGV3/dmon_ctl.pl"
CONFIGDIR="$ARGV5/config/plugins/$ARGV3"
if [ -x "$CTL" ]; then
	# stop sets the stop flag - keep the user's choice instead
	WAS_STOPPED=0
	[ -e "$CONFIGDIR/monitor_stopped" ] && WAS_STOPPED=1
	"$CTL" stop >/dev/null 2>&1
	# The MCP server runs the old code until it is restarted - boot starts it again
	"$CTL" mcp-stop >/dev/null 2>&1
	[ "$WAS_STOPPED" = "0" ] && rm -f "$CONFIGDIR/monitor_stopped"
	echo "<INFO> Receiver stopped for the upgrade."
fi

for part in config data; do
	SRC="$ARGV5/$part/plugins/$ARGV3"
	STASH="$ARGV5/$part/plugins/.$ARGV3.upgrade"
	if [ -d "$SRC" ]; then
		rm -rf "$STASH"
		mv "$SRC" "$STASH" && echo "<INFO> $part saved for the upgrade."
	fi
done
exit 0
