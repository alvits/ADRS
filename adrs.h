#ifndef _ADRS_H
#define _ADRS_H

#define EOT 0x4
#define MSG_BUFLEN 2048

#ifndef MSG_EOR
#define MSG_EOR 0x80
#endif

#ifdef DEBUG_ADRS
#define dprintf(fmt, ...) \
    printf("ADRS: " fmt, ## __VA_ARGS__)
#else
#define dprintf(fmt, ...) \
    (void) 0
#endif

int make_inet_socket (const char *ip_addr, const char *port);
int is_mounted (char * mount_path);

#endif	/* _ADRS_H */
