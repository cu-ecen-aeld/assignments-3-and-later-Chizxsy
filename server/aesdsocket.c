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

#ifndef USE_AESD_CHAR_DEVICE
#define DATA_FILE_DIR "/var/tmp/aesdsocketdata"
#else
#define DATA_FILE_DIR "/dev/aesdchar"
#endif

#define PORT "9000"
#define BUFFER_SIZE 1024
#define timestamp_interval 10

// global file pointer
FILE *data_file = NULL;

int quit_sig = 0;
int server_sockfd = -1;
pthread_mutex_t data_file_mutex;
pthread_t timer_thread;

// struct for thread id and coresponding data   
struct thread_data{
    pthread_t threadIDx;
    int client_sockfd;
    SLIST_ENTRY(thread_data) entries; // link struct to to linked list
    char client_ip[INET6_ADDRSTRLEN];
    bool threadDone;
};

// head of the signly linked list
SLIST_HEAD(slisthead, thread_data) head;

static void sighandler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        quit_sig = 1;
        if (server_sockfd != -1) {
            shutdown(server_sockfd, SHUT_RDWR);
        }
    }
}

void send_packet(int clientfd) {
    // read from beginning of file
    rewind(data_file);

    char buffer[BUFFER_SIZE];
    ssize_t b_read;
    // mutexes here cause a dead lock since the connection handler handles locking
    //pthread_mutex_lock(&data_file_mutex);

    while ((b_read = fread(buffer, 1, sizeof(buffer), data_file)) > 0) {
        if (send(clientfd, buffer, b_read, 0) == -1) {
            syslog(LOG_ERR, "Failed to send packet");
            break;
        }
    }
    //pthread_mutex_unlock(&data_file_mutex);

}

// time stamp handler
void* timestamp(void *arg){

    while(!quit_sig) {
        sleep(timestamp_interval);
        if (quit_sig) break; //run timer while active

        // get current time 
        char timestamp_str [100];
        time_t t = time(NULL);
        struct tm *temp_time = localtime(&t);

        // format time for RFC 2822
        strftime(timestamp_str, sizeof(timestamp_str), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", temp_time);

        // lock mutex
        pthread_mutex_lock(&data_file_mutex);
        
    	// write string to buffer	
        fputs(timestamp_str, data_file);
        fflush(data_file);

        // unlock mutex
        pthread_mutex_unlock(&data_file_mutex);
    }
    return NULL;
}

void* connection_handler(void* thread_param){
        struct thread_data* data = (struct thread_data*)thread_param;
        char buffer[BUFFER_SIZE];
        ssize_t b_recv;
        int newline_found = 0;

        // receive buffer
        char *recv_buffer = malloc(BUFFER_SIZE);
        size_t current_buffer_size = 0;
        size_t bigger_buffer = BUFFER_SIZE;

        // dynamically allocate memory and resize buffer to avoid overflow
        while((b_recv = recv(data->client_sockfd, buffer, sizeof(buffer), 0)) >0){
            if(current_buffer_size + b_recv > bigger_buffer){
                bigger_buffer *= 2;
		recv_buffer = realloc(recv_buffer, bigger_buffer);
            }
            // copies
            memcpy(recv_buffer + current_buffer_size, buffer, b_recv);
            current_buffer_size += b_recv;

            if (memchr(buffer, '\n', b_recv)){
                newline_found = 1; 
                break;
            }
        }

        pthread_mutex_lock(&data_file_mutex);
       
        fwrite(recv_buffer, 1, current_buffer_size, data_file);
        fflush(data_file); 
        
        pthread_mutex_unlock(&data_file_mutex);

        // free dynamically allocated buffer
        free(recv_buffer);

        // check for end of packet and send back file contents
        if (newline_found) {
            pthread_mutex_lock(&data_file_mutex);
            send_packet(data->client_sockfd);
            pthread_mutex_unlock(&data_file_mutex);
        }
        //clean up
        close(data->client_sockfd);
        syslog(LOG_INFO, "Closed connection from %s", data->client_ip);
        data->threadDone = true; 
        return 0;
}

int main(int argc, char *argv[]) {
    struct addrinfo hints, *res, *p;
    struct sigaction sa;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_sockfd;
    int status;

    struct thread_data *node, *temp_node;

    char ipstr[INET6_ADDRSTRLEN];

    SLIST_INIT(&head);
    pthread_mutex_init(&data_file_mutex, NULL);

    // open aesdsocket log. journalctl -f | grep aesdsocket
    openlog("aesdsocket", LOG_PID, LOG_USER);

    // simplified daemon mode
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        pid_t pid = fork();
        if (pid < 0) return -1;
        if (pid > 0) exit(EXIT_SUCCESS);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
        return -1;
    }

    // setup signal handler
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Failed to setup signal handler");
        return -1;
    }

    // setup socket
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

    // open the aesdsocket file. creates one if missing
    data_file = fopen(DATA_FILE_DIR, "w+");
    if (data_file == NULL){
	    syslog(LOG_ERR, "Failed to open global data file");
	    return -1;
    }

    // start timer thread
    pthread_create(&timer_thread, NULL, timestamp, NULL);

    while (!quit_sig) {
        client_addr_len = sizeof(client_addr);
        client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sockfd == -1) {
            if (quit_sig){
                break;
            }
            continue;
        }

        // create threads for each new connection
        struct thread_data *new_connection = (struct thread_data*)malloc(sizeof(struct thread_data));
        new_connection->client_sockfd = client_sockfd;
        new_connection->threadDone = false;

        void *addr = (client_addr.ss_family == AF_INET)
            ? (void *)&((struct sockaddr_in *)&client_addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)&client_addr)->sin6_addr;

        inet_ntop(client_addr.ss_family, addr, ipstr, sizeof(ipstr));
        strcpy(new_connection->client_ip, ipstr);

        syslog(LOG_INFO, "Accepted connection from %s", ipstr);

        // thread to handle new connections
        pthread_create(&new_connection->threadIDx, NULL, connection_handler, new_connection);

        // add the newly created connection node to ll
        SLIST_INSERT_HEAD(&head, new_connection, entries);

        for (node = SLIST_FIRST(&head); node != NULL; node = temp_node) {
        // store the next pointer before doing anything else
        temp_node = SLIST_NEXT(node, entries);

        if (node->threadDone) {
            pthread_join(node->threadIDx, NULL);
            SLIST_REMOVE(&head, node, thread_data, entries);
            free(node);
        }
}

        /*
        SLIST_FOREACH_SAFE(node, &head, entries, temp_node) {
            if (node->threadDone) {
                pthread_join(node->threadIDx, NULL);
                SLIST_REMOVE(&head, node, thread_data, entries);
                free(node);
            }
        }
        */
    }

    syslog(LOG_INFO, "Cleaning up threads...");
    while (!SLIST_EMPTY(&head)) {
        struct thread_data* node = SLIST_FIRST(&head);
        pthread_join(node->threadIDx, NULL);
        SLIST_REMOVE_HEAD(&head, entries);
        free(node);
    }
    pthread_join(timer_thread, NULL);
    // clean up
    fclose(data_file);
    remove(DATA_FILE_DIR);
    close(server_sockfd);
    pthread_mutex_destroy(&data_file_mutex);
    closelog();
    return 0;
}

