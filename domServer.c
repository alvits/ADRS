/* * * * * * * * * * * * * * * * * * * * * * * * * *
 * Allan Vitangcol <allan.vitangcol@oracle.com>    *
 *                                                 *
 * This program is part of the Oracle ADRS project *
 * for use on Oracle OVM and Nimbula environment.  *
 *                                                 *
 * The program can be used for other purposes      *
 * where it fits.                                  *
 *                                                 *
 * This code receives the messages from DomUs.     *
 *                                                 *
 * The program uses open source XenstoreSocket.    *
 * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include "adrs.h"
#include "xss.h"
#include <jni.h>

static pthread_mutex_t adrs_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct xs_handle *xshandle=NULL;
static char **xs_path;

static JavaVM *jvm;
jclass activityClass;
jobject activityObj;

struct threadChild {
    pthread_t child;
    unsigned int domid;
    struct threadChild *next;
};

static struct threadChild *listenerThreads=NULL;

bool newListener(const struct threadChild *listenerThreads, const unsigned int domid) {
    bool retval=true;
    while(retval && listenerThreads) {
        retval=(listenerThreads->domid != domid);
        listenerThreads=listenerThreads->next;
    }
    return retval;
}

bool notFound(const unsigned int domid, const char **const xs_path, const unsigned int numindex) {
    unsigned int counter;
    bool retval=true;
    for(counter=0; counter<numindex && retval; counter++)
        retval=(domid != strtol(xs_path[counter],NULL,10));
    return retval;
}

struct threadChild *pushThread(struct threadChild *const listenerThreads, const unsigned int domid) {
    struct threadChild *newThread;
    newThread=(struct threadChild *)malloc(sizeof(struct threadChild));
    newThread->domid=domid;
    newThread->next=listenerThreads;
    return newThread;
}

void shutdownListener(const struct threadChild *const listenerThread) {
    struct xs_handle *xsh;
    xs_transaction_t th;
    char *xss_path, eot=EOT;
    unsigned int len;
    xsh=XS_OPEN(0);
    len=snprintf(NULL, 0, "xss/%d/buffer", listenerThread->domid)+1;
    xss_path=malloc(len);
    memset(xss_path,0,len);
    sprintf(xss_path, "xss/%d/buffer", listenerThread->domid);
    th = xs_transaction_start(xsh);
    xs_write(xsh, th, xss_path, &eot, 1);
    memset(xss_path,0,len);
    sprintf(xss_path, "xss/%d/evtchn", listenerThread->domid);
    xs_write(xsh, th, xss_path, "0:xss/0", 7);
    xs_transaction_end(xsh, th, false);
    XS_CLOSE(xsh);
    free(xss_path);
}

struct threadChild *popThreads(struct threadChild *const listenerThreads, const char **const xs_path, const unsigned int numindex) {
    struct threadChild *retval;
    if(listenerThreads) {
        if(pthread_kill(listenerThreads->child, 0)) {
            retval=listenerThreads->next;
            free(listenerThreads);
        } else
            if(notFound(listenerThreads->domid, xs_path, numindex)) {
                shutdownListener(listenerThreads);
                retval=listenerThreads->next;
                free(listenerThreads);
            } else
                retval=listenerThreads;
        if(retval)
            retval->next=popThreads(retval->next, xs_path, numindex);
        return retval;
    } else
        return NULL;
}

void create_listener(const unsigned int *const domid) {
    const unsigned int const domainID=*domid;
    struct xs_sock *xss_listener, *xss_source;
    char *xss_instance, buffer[ENTRYSIZE];
    unsigned int len;
    JNIEnv *env;
    jint rs = (*jvm)->AttachCurrentThread(jvm, (void **)&env, NULL);
    //assert (rs == JNI_OK);
    xss_source=malloc(sizeof(struct xs_sock));
    memset(xss_source->addr,0,ENTRYSIZE);
    sprintf(xss_source->addr, "xss/%u", 0);
    xss_source->domid=domainID;
    xss_source->xsh=NULL;
    len=snprintf(NULL, 0, "xss/%u", domainID)+1;
    xss_instance=malloc(len);
    memset(xss_instance,0,len);
    sprintf(xss_instance, "xss/%u", domainID);
    if((xss_listener=xss_open(xss_instance)) != NULL) {
        memset(buffer,0,ENTRYSIZE);
        while(xss_recvfrom(xss_listener,buffer,ENTRYSIZE,xss_source) > 0 && *buffer != EOT) {
#ifdef TWO_WAY
            char *formatMessage = malloc(snprintf(NULL, 0, "{ \"domainid\": %u, \"message\": %s}", domainID, buffer)+1);
            sprintf(formatMessage, "{ \"domainid\": %u, \"message\": %s}", domainID, buffer);
            jmethodID notificationMethod = (*env)->GetMethodID(env, activityClass, "handleMessage", "(ILjava/lang/String;)Ljava/lang/String;");
            jobject notificationObj = (*env)->CallObjectMethod(env, activityObj, notificationMethod, domainID, (*env)->NewStringUTF(env, formatMessage));
            (*env)->ReleaseStringUTFChars(env, notificationObj, formatMessage);
            const char *repbuffer = (*env)->GetStringUTFChars(env, notificationObj, 0);
            xss_sendto(xss_listener,(char *)repbuffer,strlen(repbuffer),xss_source);
            (*env)->ReleaseStringUTFChars(env, notificationObj, repbuffer);
#endif
            memset(buffer,0,ENTRYSIZE);
        }
        xss_close(xss_listener);
    }
    free(xss_instance);
    if(xss_source->xsh)
        free(xss_source->xsh);
    free(xss_source);
    rs = (*jvm)->DetachCurrentThread(jvm);
    //assert (rs == JNI_OK);
    return;
}

int getDomainId(void) {
    xs_transaction_t th;
    struct xs_handle *xshandle=NULL;
    char *dompath;
    unsigned int domid;
    openlog("ADRS", LOG_CONS | LOG_PID, LOG_USER);
    if((xshandle = XS_OPEN(0)) == NULL) {
        syslog(LOG_ERR, "Cannot open xen domain. %s", strerror(errno));
        closelog();
        return -1;
    }
    th = xs_transaction_start(xshandle);
    dompath = xs_read(xshandle, th, "domid", &domid);
    xs_transaction_end(xshandle, th, false);
    domid = strtol(dompath,NULL,10);
    free(dompath);
    XS_CLOSE(xshandle);
    closelog();
    return domid;
}

JNIEXPORT jint JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_getDomainId (JNIEnv *env, jobject obj) {
    return getDomainId();
}

void stopListeners(void) {
    struct threadChild *track;
    dprintf("Waiting for lock to stop all listeners.\n");
    if(pthread_mutex_lock(&adrs_mutex) == 0) {
        dprintf("Lock acquired. Stopping all listeners.\n");
        while(listenerThreads != NULL) {
            shutdownListener(listenerThreads);
            track=listenerThreads;
            listenerThreads=listenerThreads->next;
            free(track);
        }
        if(xshandle != NULL) {
            xs_rm(xshandle, XBT_NULL, "/local/domain/0/xss");
            free(xshandle);
        }
        if(xs_path != NULL)
            free(xs_path);
        closelog();
        pthread_mutex_unlock(&adrs_mutex);
        dprintf("Lock released. All listeners are now stopped.\n");
    }
    return;
}

JNIEXPORT void JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_stopListeners (JNIEnv *env, jobject obj) {
    stopListeners();
}

void startListeners(void) {
    pthread_attr_t attr;
    sigset_t signals2block;
    xs_transaction_t th;
    struct xs_permissions perms[1];
    unsigned int domid, numindex, counter;
    char *dompath, *token, *xss_path;
    perms[0].perms = XS_PERM_READ|XS_PERM_WRITE;
    openlog("ADRS", LOG_CONS | LOG_PID, LOG_USER);
    if(pthread_attr_init(&attr) || pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
        syslog(LOG_ERR, "Failed to set thread attributes. %s", strerror(errno));
        closelog();
        return;
    }
    sigemptyset(&signals2block);
    sigaddset(&signals2block, SIGINT);
    sigaddset(&signals2block, SIGQUIT);
    sigaddset(&signals2block, SIGTERM);
    sigaddset(&signals2block, SIGUSR1);
    sigaddset(&signals2block, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &signals2block, NULL);
    if((xshandle = XS_OPEN(0)) == NULL) {
        syslog(LOG_ERR, "Cannot open xen domain. %s", strerror(errno));
        closelog();
        return;
    }
    th = xs_transaction_start(xshandle);
    dompath = xs_read(xshandle, th, "domid", &domid);
    domid = strtol(dompath,NULL,10);
    free(dompath);
    dompath = xs_get_domain_path(xshandle,domid);
    if((token = strrchr(dompath, '/')))
        *token='\0';
    xs_transaction_end(xshandle, th, false);
    while(pthread_mutex_lock(&adrs_mutex) == 0) {
        th = xs_transaction_start(xshandle);
        free(xs_path); xs_path=NULL;
        xs_path = xs_directory(xshandle, th, dompath, &numindex);
        xs_transaction_end(xshandle, th, false);
        for(counter=0; counter < numindex; counter ++) {
            domid = strtol(xs_path[counter],NULL,10);
            if(domid > 0)
                if(newListener(listenerThreads, domid)) {
                    listenerThreads=pushThread(listenerThreads, domid);
                    th = xs_transaction_start(xshandle);
                    int len = snprintf(NULL, 0,"%s/%u/xss",dompath,domid)+1;
                    xss_path=malloc(len);
                    memset(xss_path,0,len);
                    sprintf(xss_path,"%s/%u/xss",dompath,domid);
                    perms[0].id = domid;
                    if(xs_mkdir(xshandle,th,xss_path))
                        xs_set_permissions(xshandle, th, xss_path, perms, 1);
                    free(xss_path);
                    xs_transaction_end(xshandle, th, false);
                    if(pthread_create(&(listenerThreads->child), &attr, (void *)&create_listener, (void *)&domid))
                        syslog(LOG_CRIT, "Unable to create thread. %s", strerror(errno));
                    sleep(1);
                }
        }
        listenerThreads=popThreads(listenerThreads, (const char **)xs_path, numindex);
        pthread_mutex_unlock(&adrs_mutex);
        sleep(30);
    };
    closelog();
    return;
}

JNIEXPORT void JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_startListeners (JNIEnv *env, jobject obj) {
    jint rs;
    rs = (*env)->GetJavaVM(env, &jvm);
    jclass cls = (*env)->GetObjectClass(env, obj);
    activityClass = (jclass) (*env)->NewGlobalRef(env, cls);
    activityObj = (*env)->NewGlobalRef(env, obj);
    startListeners();
}
