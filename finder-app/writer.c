#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
     	openlog("finderapp", LOG_PID, LOG_USER);
	// verify there are two addional args file and string besides the filename
	if (argc != 3) {
		syslog(LOG_INFO, "Two arguments required");
		exit(1);
	}

	char *writefile = argv[1];
	char *writestr = argv[2];
	//open file writer
	FILE *writer = fopen(writefile, "w");
	if (writer == NULL) {
		syslog(LOG_ERR, "Error opening file");
		exit(1);
	}
	//write string to file
	if (fprintf(writer, "%s", writestr) < 0){
		syslog(LOG_ERR, "Error writing to file");
		fclose(writer);
		exit(1);
	}

	syslog(LOG_DEBUG, "Writing %s to %s", writefile, writestr);

	//clean
	fclose(writer);
	closelog();
}
