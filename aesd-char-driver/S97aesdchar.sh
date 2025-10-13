#!/bin/sh

case "$1" in
    start)
        echo "Loading aesdchar driver"
        /usr/bin/aesdchar_load
        ;;
    stop)
        echo "Unloading aesdchar driver"
        /usr/bin/aesdchar_unload
        ;;
    restart|reload)
        "$0" stop
        "$0" start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
esac

exit 0
