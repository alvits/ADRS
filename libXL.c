#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <libxl.h>
#include <libxl_utils.h>
#include <proc/procps.h>
#include <proc/readproc.h>
#include <jni.h>
#include "xss.h"

void freeproc(proc_t* p) {
    if (!p)	/* in case p is NULL */
	return;
    /* ptrs are after strings to avoid copying memory when building them. */
    /* so free is called on the address of the address of strvec[0]. */
    if (p->cmdline)
	free((void*)*p->cmdline);
    if (p->environ)
	free((void*)*p->environ);
    free(p);
}

pid_t getDomainProcessID(const char *const domainName) {
    PROCTAB *pt;
    proc_t *proc_entry;
    pid_t retval=0L;
    bool found=false;
    pt=openproc(PROC_FILLCOM);
    if(pt != NULL && domainName != NULL) {
        while((proc_entry=readproc(pt, NULL)) != NULL && !found) {
            unsigned int counter=0;
            if(proc_entry->cmdline != NULL) {
                while(proc_entry->cmdline[counter++] != NULL) {
                    if(strstr(proc_entry->cmdline[counter-1],domainName) != NULL) {
                        retval=proc_entry->tid;
                        found=true;
                        break;
                    }
                }
            }
            freeproc(proc_entry);
        }
        freeproc(proc_entry);
    }
    if(pt != NULL)
        closeproc(pt);
    return retval;
}

int setVCPUs(int domid, unsigned int newVCPUs) {
    int retval=-1;
    libxl_ctx *ctx=NULL;
    libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, NULL);
    libxl_bitmap cpumap;
    unsigned int i=0, host_cpu;
    if(ctx != NULL) {
        host_cpu=libxl_get_max_cpus(ctx);
        if(host_cpu > newVCPUs)
            host_cpu = newVCPUs;
        if(libxl_cpu_bitmap_alloc(ctx, &cpumap, host_cpu)) {
             syslog(LOG_ERR, "libxp_cpu_bitmap_alloc failed for domain %u\n", domid);
        } else {
             for(i=0; i < host_cpu; i++)
                  libxl_bitmap_set(&cpumap, i);
             retval=libxl_set_vcpuonline(ctx, domid, &cpumap);
             libxl_bitmap_dispose(&cpumap);
        }
        libxl_ctx_free(ctx);
    }
    return retval;
}

JNIEXPORT jint JNICALL Java_com_oracle_pdit_adrs_xen_Xl_setVCPUs (JNIEnv *env, jobject obj, jint domid, jint newVCPUs) {
    return setVCPUs(domid, newVCPUs);
}

int setMemoryTarget(int domid, unsigned long newMemorySizeInBytes) {
    int retval=-1;
    long StaticMax=snprintf(NULL, 0, "/local/domain/%u/memory/static-max", domid)+1, len=0;
    libxl_ctx *ctx;
    libxl_dominfo domInfo;
    struct xs_handle *xshandle;
    char *StaticMaxPath=malloc(StaticMax), *strStaticMax;
    libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, NULL);
    if(StaticMaxPath != NULL) {
        memset(StaticMaxPath, 0, StaticMax);
        sprintf(StaticMaxPath, "/local/domain/%u/memory/static-max", domid);
        if(ctx != NULL) {
            if((xshandle = XS_OPEN(0)) != NULL) {
                libxl_domain_info(ctx, &domInfo, domid);
                if((strStaticMax=xs_read(xshandle, XBT_NULL, StaticMaxPath, NULL)) == NULL) {
                    len=snprintf(NULL, 0, "%lu", domInfo.max_memkb);
                    strStaticMax=malloc(len+1);
                    memset(strStaticMax, 0, len+1);
                    sprintf(strStaticMax, "%lu", domInfo.max_memkb);
                    xs_write(xshandle, XBT_NULL, StaticMaxPath, strStaticMax, len);
                }
                free(strStaticMax);
                retval=libxl_set_memory_target(ctx, domid, (domInfo.max_memkb > ((newMemorySizeInBytes + 1023) / 1024) ? (newMemorySizeInBytes + 1023) / 1024 : domInfo.max_memkb), 0, 0);
                if(len)
                    xs_rm(xshandle, XBT_NULL, StaticMaxPath);
                XS_CLOSE(xshandle);
            }
            libxl_ctx_free(ctx);
        }
        free(StaticMaxPath);
    }
    return retval;
}

JNIEXPORT jint JNICALL Java_com_oracle_pdit_adrs_xen_Xl_setMemoryTarget (JNIEnv *env, jobject obj, jint domid, jlong newMemorySizeInBytes) {
    return setMemoryTarget(domid, newMemorySizeInBytes);
}

long getFreeMemory(void) {
    libxl_ctx *ctx;
    uint32_t retval=-1;
    libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, NULL);
    if(ctx != NULL) {
        libxl_get_free_memory(ctx, &retval);
        libxl_ctx_free(ctx);
    }
    return retval;
}

JNIEXPORT jlong JNICALL Java_com_oracle_pdit_adrs_xen_Xl_getFreeMemory (JNIEnv *env, jobject obj) {
    return getFreeMemory();
}

jobjectArray getDomains(JNIEnv *env, jobject obj) {
    int counter;
    int numindex;
    libxl_ctx *ctx;
    libxl_dominfo *domainList;
    libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, NULL);
    if(ctx != NULL) {
        if((domainList=libxl_list_domain(ctx, &numindex)) != NULL) {
            if(numindex) {
                jclass classDomain = (*env)->FindClass(env, "com/oracle/pdit/adrs/xen/Domain");
                jmethodID classDomainInit = (*env)->GetMethodID(env, classDomain, "<init>", "(ILjava/lang/String;JLjava/lang/String;JJ)V");
                jobjectArray retval = (*env)->NewObjectArray(env, numindex, classDomain, NULL);
                for(counter=0; counter < numindex; counter ++) {
                    char *domainName=libxl_domid_to_name(ctx, domainList[counter].domid);
                    char *domainUUID = malloc(37);
                    memset(domainUUID,0,37);
                    uuid_unparse(domainList[counter].uuid.uuid, domainUUID);
                    jobject domObj = (*env)->NewObject(env, classDomain, classDomainInit, domainList[counter].domid, (*env)->NewStringUTF(env, domainName), getDomainProcessID(domainName), (*env)->NewStringUTF(env, domainUUID), domainList[counter].max_memkb, domainList[counter].current_memkb, domainList[counter].vcpu_online, domainList[counter].vcpu_max_id+1);
                    (*env)->SetObjectArrayElement(env, retval, counter, domObj);
                    free(domainUUID);
                    free(domainName);
                }
                libxl_dominfo_list_free(domainList,numindex);
                libxl_ctx_free(ctx);
                return retval;
            }
            libxl_dominfo_list_free(domainList,numindex);
        }
        libxl_ctx_free(ctx);
    }
    return NULL;
}

JNIEXPORT jobjectArray JNICALL Java_com_oracle_pdit_adrs_xen_Xl_getDomains (JNIEnv *env, jobject obj) {
    return getDomains(env, obj);
}
