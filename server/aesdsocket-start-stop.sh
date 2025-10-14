#!/bin/sh

case "$1" in
    start)
        echo "Starting aesdsocket server"
        # Use ./aesdsocket to specify the executable in the current directory
        start-stop-daemon -S -a /usr/bin/aesdsocket -- -d
        ;;
    stop)
        echo "Stopping aesdsocket server"
        # Use -K to stop the daemon by executable path
        start-stop-daemon -K -a /usr/bin/aesdsocket
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
esac

exit 0
