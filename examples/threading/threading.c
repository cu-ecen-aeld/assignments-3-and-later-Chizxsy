#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>


void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    
    int rc;

    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    //wait
    usleep(thread_func_args->time1*1000);
    //obtain mutex
    rc = pthread_mutex_lock(thread_func_args->pthread_mutex);
    if (rc) {
	    syslog(LOG_CRIT, "Obtain Mutex; rc is %d\n", rc);
	    thread_func_args->thread_complete_success=false;
	    return thread_param;
    }
    //wait
    usleep(thread_func_args->time2*1000);
    //release mutex
    rc = pthread_mutex_unlock(thread_func_args->pthread_mutex);
    if (rc) {
	    syslog(LOG_CRIT, "Release Mutex; rc is %d\n", rc);
    	    thread_func_args->thread_complete_success=false;
	    return thread_param;
    }
    thread_func_args->thread_complete_success=true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    int rc;
    
    struct thread_data *thread_params = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (thread_params == NULL){
	    return false;
    }

    //init struct members
    thread_params->time1=wait_to_obtain_ms;
    thread_params->time2=wait_to_release_ms;
    thread_params->pthread_mutex=mutex;
    thread_params->thread_complete_success=false;

    rc = pthread_create(thread, NULL, threadfunc, thread_params);
    if (rc) {
	    syslog(LOG_CRIT, "pthread_create; rc is %d\n", rc);
	    free(thread_params);

	    return false;
    }

    return true;
}

