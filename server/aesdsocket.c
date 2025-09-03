#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <time.h>

#define PORT "9000"
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024
#define TIME_INTERVAL 10

int quit_sig = 0;
int server_sockfd = -1;
pthread_mutex_t data_file_mutex;

// struct for thread id and coresponding data   
struct thread_data{
    pthread_t threadIDx;
    int client_sockfd;
    SLIST_ENTRY(thread_data) entries; // link struct to to linked list
}

// singly linked list head
SLIST_HEAD(slisthead, thread_data) head;

static void sighandler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        quit_sig = 1;
        remove(DATA_FILE);
        if (server_sockfd != -1) {
            shutdown(server_sockfd, SHUT_RDWR);
        }
    }
}

void send_packet(int clientfd) {
    int fd = open(DATA_FILE, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "Failed to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t b_read;
    while ((b_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (send(clientfd, buffer, b_read, 0) == -1) {
            syslog(LOG_ERR, "Failed to send packet");
            break;
        }
    }

    close(fd);
}

// time stamp handler
void *timestamp(void *arg){
    while(!quit_sig) {
        if (quit_sig) break; //run timer while active

        // get current time 
        char timestamp_str [100];
        time_t t = time(NULL);
        struct tm *tmp = localtime(&t);

        // format time for RFC 2822
        strftime(timestamp_str, sizeof(timestamp_str), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tmp_time);

        // lock mutex
        pthread_mutex_lock(&data_file_mutex);
        
        // intert time stamp into file
        FILE *data_file = fopen(DATA_FILE, "a+");
        if (!data_file) {
            syslog(LOG_ERR, "Failed to open file for time stamp");
            
            
        } else {
            fputs(timestamp_str, data_file);
            fclose(data_file);
        }
        
        // unlock mutex
        pthread_mutex_unlock(&data_file_mutex);
    }
    return NULL;

int main(int argc, char *argv[]) {
    struct addrinfo hints, *res, *p;
    struct sigaction sa;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_sockfd;
    int status;
    int daemon_mode = 0;

    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
    }

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
        return -1;
    }

    openlog("aesdsocket", LOG_PID, LOG_USER);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Failed to setup signal handler");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, PORT, &hints, &res)) != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(status));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        server_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (server_sockfd == -1) continue;

        int yes = 1;
        setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(server_sockfd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(server_sockfd);
    }

    freeaddrinfo(res);

    if (!p) {
        syslog(LOG_ERR, "Failed to bind socket");
        return -1;
    }

    if (listen(server_sockfd, 10) == -1) {
        syslog(LOG_ERR, "Failed to listen");
        close(server_sockfd);
        return -1;
    }

    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) return -1;
        if (pid > 0) exit(EXIT_SUCCESS);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    while (!quit_sig) {
        client_addr_len = sizeof(client_addr);
        client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sockfd == -1) continue;

        char ipstr[INET6_ADDRSTRLEN];
        void *addr = (client_addr.ss_family == AF_INET)
            ? (void *)&((struct sockaddr_in *)&client_addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)&client_addr)->sin6_addr;

        inet_ntop(client_addr.ss_family, addr, ipstr, sizeof(ipstr));
        syslog(LOG_INFO, "Accepted connection from %s", ipstr);

        FILE *data_file = fopen(DATA_FILE, "a+");
        if (!data_file) {
            syslog(LOG_ERR, "Failed to open/create datafile");
            close(client_sockfd);
            continue;
        }

        char buffer[BUFFER_SIZE];
        ssize_t b_recv;
        int newline_found = 0;
        while ((b_recv = recv(client_sockfd, buffer, sizeof(buffer), 0)) > 0) {
            fwrite(buffer, 1, b_recv, data_file);
            if (memchr(buffer, '\n', b_recv)) {
                newline_found = 1;
                break;
            }
        }

        fclose(data_file);

        if (newline_found) {
            send_packet(client_sockfd);
        }

        close(client_sockfd);
        syslog(LOG_INFO, "Closed connection from %s", ipstr);
    }

    close(server_sockfd);
    remove(DATA_FILE);
    closelog();
    return 0;
}

