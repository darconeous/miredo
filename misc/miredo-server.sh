#!/bin/sh
# $Id$
#
# miredo-server start/stop script for Debian GNU/Linux
# Author: Remi Denis-Courmont <rdenis (at) simphalempin (dot) com>
#
# chkconfig: 345 17 83
# description: Starts and stops the miredo-servre daemon \
#	       used to provide a Teredo server.
#
### BEGIN INIT INFO
# Requires: $local_fs $network $syslog $time
# Short-Description: Teredo server
# Description: miredo-server daemon to provide a Teredo server
# Default-Start: 3 4 5
# Default-Stop: 0 1 2 6
### END INIT INFO


PATH=/sbin:/usr/sbin:/bin:/usr/bin
DAEMON=/usr/sbin/miredo-server
NAME=miredo-server
DESC="Teredo server daemon"
DAEMON_ARGS=""
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

CONF=/etc/default/$NAME

# Source configuration.
[ -r $CONF ] && . $CONF

test -x $DAEMON || exit 0

case "$1" in
  start)
	if [ "$STARTMIREDO_SERVER" != "true" ]; then
		echo "STARTMIREDO_SERVER is set to false in $CONF"
		echo "$DAEMON not starting"
		exit 0
	fi
	echo -n "Starting $DESC: $NAME"
	start-stop-daemon --start --quiet --pidfile $PIDFILE \
		--exec $DAEMON -- $DAEMON_ARGS
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC: $NAME"
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --retry 1
	echo "."
	;;
  reload|force-reload)
	echo -n "Reloading $DESC: $NAME"
	start-stop-daemon --stop --signal 1 --quiet --exec $DAEMON
	echo "."
	;;
  restart)
	echo -n "Restarting $DESC: $NAME"
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --retry 1 --oknodo
	start-stop-daemon --start --quiet --pidfile $PIDFILE \
		--exec $DAEMON -- $DAEMON_ARGS
	echo "."
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	exit 1
	;;
esac

exit 0

