/* * * * * * * * * * * * * * * * * * * * * * * * * *
 * Allan Vitangcol <allan.vitangcol@oracle.com>    *
 *                                                 *
 * This program is part of the Oracle ADRS project *
 * for use on Oracle OVM and Nimbula environment.  *
 *                                                 *
 * The program can be used for other purposes      *
 * where it fits.                                  *
 *                                                 *
 * This is the client code for DomUs to allow      *
 * sending messages to Dom0.                       *
 *                                                 *
 * The program uses open source XenstoreSocket     *
 * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <sys/mount.h>
#include <jni.h>
#include "adrs.h"
#include "xss.h"

static pthread_mutex_t adrs_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct xs_sock *xss_listener, xss_dest;
static int mounted=1;

int prepareConnection(void) {
    int retval=-1;
    struct xs_handle *xshandle;
    char xss_instance[ENTRYSIZE], *chardomid;
    if(!is_mounted("/proc/xen"))
        if((mounted = mount("xenfs", "/proc/xen", "xenfs", 0, NULL)) != 0) {
            syslog(LOG_ERR, "Failed to mount /proc/xen. %s", strerror(errno));
            printf("Failed to mount /proc/xen.\n");
            return retval;
        }
    if(pthread_mutex_lock(&adrs_mutex) == 0) {
        if((xshandle = XS_OPEN(0)) == NULL) {
            syslog(LOG_CRIT, "Failed to open xen domain. %s", strerror(errno));
            return retval;
        }
        memset(xss_dest.addr,0,ENTRYSIZE);
        chardomid=xs_read(xshandle, XBT_NULL, "domid", &xss_dest.domid);
        XS_CLOSE(xshandle);
        sprintf(xss_dest.addr, "xss/%s", chardomid);
        xss_dest.domid=0;
        xss_dest.xsh=NULL;
        memset(xss_instance,0,ENTRYSIZE);
        sprintf(xss_instance, "xss/%u", xss_dest.domid);
        dprintf("Opening listener on %s for domain %s\n", xss_instance, chardomid);
        if((xss_listener=xss_open(xss_instance)) != NULL) {
    	    dprintf("Successful opening listener on %s for domain %s\n", xss_instance, chardomid);
            retval=0;
        } else {
    	    dprintf("Failed opening listener on %s for domain %s\n", xss_instance, chardomid);
        }
        free(chardomid);
        pthread_mutex_unlock(&adrs_mutex);
    }
    return retval;
}

JNIEXPORT jint JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_prepareConnection (JNIEnv *env, jobject obj) {
    return prepareConnection();
}

void destroyConnection(void) {
    if(pthread_mutex_lock(&adrs_mutex) == 0) {
        if(xss_dest.xsh)
            free(xss_dest.xsh);
        xss_close(xss_listener);
        if(mounted == 0 )
            umount("/proc/xen");
        pthread_mutex_unlock(&adrs_mutex);
    }
}

JNIEXPORT void JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_destroyConnection (JNIEnv *env, jobject obj) {
        destroyConnection();
}

char *sendNreceive(char *message) {
    char *retval=NULL;
    if(pthread_mutex_lock(&adrs_mutex) == 0) {
        if(xss_sendto(xss_listener,message,strlen(message),&xss_dest) < 0) {
            retval=strdup("{\"Error\":\"Unable to send message.\"}");
        } else {
#ifdef TWO_WAY
            if(((char *)message)[0] != EOT) {
                retval=malloc(ENTRYSIZE);
                memset(retval,0,ENTRYSIZE);
                xss_recvfrom(xss_listener,retval,ENTRYSIZE,&xss_dest);
            }
        }
#endif
        pthread_mutex_unlock(&adrs_mutex);
    }
    return retval;
}

JNIEXPORT jstring JNICALL Java_com_oracle_pdit_adrs_xen_XenStore_sendNreceive (JNIEnv *env, jobject obj, jstring message) {
    char *buffer, *returnchar;
    jstring retval=NULL;
    buffer = (char*)(*env)->GetStringUTFChars(env, message, 0);
    returnchar = sendNreceive(buffer);
    (*env)->ReleaseStringUTFChars(env, obj, buffer);
    retval = (*env)->NewStringUTF(env, returnchar);
    (*env)->ReleaseStringUTFChars(env, obj, returnchar);
    return retval;
}
