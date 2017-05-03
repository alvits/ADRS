# make with GCOV='-fprofile-arcs -ftest-coverage' to test coverage

ifndef JAVA_HOME
    ifneq ("$(wildcard /usr/java/latest)","")
        JAVA_HOME:=/usr/java/latest
    else
        $(error JAVA_HOME is not set)
    endif
else
    ifeq ("$(wildcard $(JAVA_HOME)/bin/javac)","")
        $(error jdk is not installed)
    endif
endif

CC:=gcc
UNAME:=$(shell uname)
XENVERSION:=$(shell rpm -q --qf "%{version}" xen-devel | cut -c1)
CFLAGS:=-fpic -O2 -Wall -Wextra -D_XOPEN_SOURCE=700 -D__USE_POSIX=2000 -D$(UNAME) -DXENVERSION=$(XENVERSION) -DMTAB=\"/proc/self/mounts\" -DTWO_WAY -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux $(DEBUG) $(GCOV)
ADRS:=libADRS.so
LIBPROC:=$(shell (rpm -q procps-ng-devel > /dev/null 2>&1 && echo procps) || (rpm -q procps-devel > /dev/null 2>&1 && echo proc))
LDFLAGS:=-Wall -Wextra -lpthread -pthread -l$(LIBPROC) -lxenlight -shared -e project $(GCOV)
TEMPFILE:=$(shell mktemp -u /tmp/XXXXXXXXXX)
TESTOUT:=$(TEMPFILE)
TESTSOURCE:=$(TEMPFILE).c
INTERP:=$(shell echo -e "int main(int argc, char *argv[]){(void *)0;}" > $(TESTSOURCE); $(CC) $(CCFLAGS) $(TESTSOURCE) -o $(TESTOUT) > /dev/null 2>&1; readelf -l $(TESTOUT)|grep Requesting\ program\ interpreter|sed 's/^[^:]*:[[:blank:]]\([^]]*\).*/\1/g'; rm -f $(TESTSOURCE) $(TESTOUT))
JNISOURCES:=$(shell grep -l JNIEXPORT *.c)

ifndef LIBPROC
    $(error procps development package is not installed)
endif

all:	$(ADRS)

clean:
	rm -f *.o *.gc?? *.so project.?

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

project.c: README $(JNISOURCES)
	echo '#include <unistd.h>' > $@
	echo '#include <stdio.h>' >> $@
	echo 'const char service_interp[] __attribute__((section(".interp"))) = "$(INTERP)";' >> $@
	echo 'void project(void) {' >> $@
	echo 'printf("\n");' >> $@
	sed 's/^\(.*\)/printf("\1\\n");/' $< >> $@
	echo 'printf("\n");' >> $@
	echo 'printf("This library provides the following JNI methods:\n");' >> $@
	echo 'printf("\n");' >> $@
	sed -n 's/^JNIEXPORT[[:blank:]]\([^[:blank:]]*\)[[:blank:]]\([^_]*_\)\+\([^[:blank:]]*\).*obj[^ )]*[ ]*\([^)]*)\).*/printf("\1 \3(\4\\n");/p' $(JNISOURCES) >> $@
	echo 'printf("\n");' >> $@
	echo 'printf("JNI full method paths:\n");' >> $@
	echo 'printf("\n");' >> $@
	sed -n '/^JNIEXPORT/{s/^JNIEXPORT[[:blank:]]\([^[:blank:]]*\)[[:blank:]]JNICALL[[:blank:]]\(\([^_]*_\)\+\)\([^[:blank:]]*\).*obj[^ )]*[ ]*\([^)]*)\).*/printf("\1 \2\4(\5\\n");/;s|_|/|gp}' $(JNISOURCES) >> $@
	echo 'printf("\n");' >> $@
	echo '_exit(0);' >> $@
	echo '}' >> $@

$(ADRS): libXL.o domServer.o domClient.o xss.o mntent.o project.o
	$(CC) $(LDFLAGS) -o $@ $^
	rm -f $^ project.?
