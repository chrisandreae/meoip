#ifndef __TUNNEL_H
#define __TUNNEL_H

#include <sys/socket.h>
#include <net/if.h>

struct gre_host;

struct tunnel{
    char 		     name[IFNAMSIZ];
    unsigned short   id;
	struct gre_host* dest;

    int              tun_fd;
    struct ifreq	 ifr;
};

#if defined(__linux__)
	#define TUNNEL_DEV "/dev/net/tun"
#elif defined(__FreeBSD__)
	#define TUNNEL_DEV "/dev/tap"
#elif defined(__APPLE__)
#else
	#error "Unsupported platform"
#endif

struct tunnel* tunnel_alloc();

/* Comparator for tunnels, compare by gre_host and tunnel id */
int tunnel_compar(const void* _t1, const void* _t2);

/* Create a new tunnel with the provided data */
struct tunnel* tunnel_new(char* name, unsigned short tunnel_id,
						  struct gre_host* host);

/* Opens and configures the tunnel device */
void tunnel_open(struct tunnel *tunnel);

/* Closes the tunnel device */
void tunnel_close(struct tunnel* t);




#endif
