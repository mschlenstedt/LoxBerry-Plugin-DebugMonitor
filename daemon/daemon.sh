#!/bin/bash

# Called by LoxBerry as root at every boot. Installed as
# system/daemons/plugins/<NAME> below the LoxBerry home directory, so the own
# file name is the plugin name.
#
# The receiver must run as loxberry - otherwise the PID file and the logs
# belong to root and the web interface can neither stop nor restart it.
[ "$(id -u)" -eq 0 ] && exec su loxberry --preserve-environment -s /bin/bash -c "$0 $*"

PLUGINNAME=$(basename "$0")
CTL="$LBPBIN/$PLUGINNAME/dmon_ctl.pl"

# The ctl script respects the stop flag: a monitor stopped by the user stays
# stopped after a reboot. Returns quickly, the receiver runs detached.
[ -x "$CTL" ] && "$CTL" boot
exit 0
