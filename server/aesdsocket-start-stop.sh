#! /bin/sh


case "$1" in 
	start)
		echo "Starting Server"
		start-stop-daemon -S -n aesdsocket -a aesdsocket
		;;
	stop)
		echo "Stopping Server"
		start-stop-daemon -S -n aesdsocket -a aesdsocket
		;;
	*)
		echo "Usage: $0 {start|stop}"
	exit 1
esac

exit 0


