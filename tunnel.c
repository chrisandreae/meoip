#include "tunnel.h"
#include "gre_host.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>

#if defined(__linux__)
	#include <netinet/ether.h>
	#include <linux/if_tun.h>
#elif defined(__FreeBSD__)
	#include <net/if_tap.h>
#endif

extern int gVerbose;

struct tunnel* tunnel_alloc(){						
	struct tunnel* n = malloc(sizeof(struct tunnel));	
	memset(n, 0x0, sizeof(struct tunnel));		
	return n;								
}

/* compare gre_host and tunnel id */
int tunnel_compar(const void* _t1, const void* _t2) {
    struct tunnel* t1 = *(struct tunnel**) _t1;
    struct tunnel* t2 = *(struct tunnel**) _t2;
	if(t1->dest != t2->dest){
		return t1->dest < t2->dest ? -1 : 1;
	}
	else return t1->id - t2->id;
}

struct tunnel* tunnel_new(char* name, int tunnel_id, struct gre_host* host) {	

	/* Create and populate a new tunnel */
	struct tunnel* tun = tunnel_alloc();
	
	tun->dest = host;

    strncpy(tun->name, name, sizeof(tun->name));
    tun->name[sizeof(tun->name) - 1] = '\0';

    tun->id = tunnel_id;
    if (tunnel_id == 0 || tunnel_id > 65536) {
		fprintf(stderr, "ID of \"%d\" is not correct\n", tun->id);
		exit(-1);
    }
	return tun;
}

void tunnel_open(struct tunnel *tunnel) {

    memset(&tunnel->ifr, 0x0, sizeof(tunnel->ifr));

#if defined(__APPLE__)
	/* on MacOS, there is no way to get a "next" tap device, so we
	 need to iterate through each of them, attempting to open.  On
	 first success, we remember the name. */
	int tapdev;
	char path[40];
	for(tapdev = 0; tapdev < 16; ++tapdev){
		sprintf(path, "/dev/tap%d", tapdev);
		if(gVerbose >= 3) printf("Attempting to open device %s: ", path);
		if((tunnel->tun_fd = open(path, O_RDWR)) > 0){
			/* success - save the name in the IFR so we can bring it
			   up */
			if(gVerbose >= 3) printf("Success (socket %d)\n", tunnel->tun_fd);
			sprintf(tunnel->ifr.ifr_name, "tap%d", tapdev);
			break;
		}
		else{
			if(gVerbose >= 3) printf("Failed", tunnel->tun_fd);
		}
	}
	if(tunnel->tun_fd < 0){
		fprintf(stderr, "open_tun: /dev/net/tun error: %s", strerror(errno));
		exit(1);
	}
#else
	/* On other platforms, we have a generic device to open. */
	if ((tunnel->tun_fd = open(TUNNEL_DEV, O_RDWR)) < 0) {
		fprintf(stderr, "open_tun: %s error: %s", TUNNEL_DEV, strerror(errno));
		exit(1);
	}
#endif	

	/* Linux: set tunnel flags and name */
#if defined(__linux__)
    tunnel->ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (tunnel->name[0] != 0) {
		strncpy(tunnel->ifr.ifr_name, tunnel->name, IFNAMSIZ);
    }
    else {
		strncpy(tunnel->ifr.ifr_name, "meoip%d", IFNAMSIZ);
    }

    if (ioctl(tunnel->tun_fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
		perror("Failed to create tunnel interface");
		exit(1);
    }
#elif defined(__FreeBSD__)
	/* When creating a device with /dev/tap on BSD, we don't get to
	   set the name. We can find out what it actually is called with
	   the TAPGIFNAME ioctl, and use that to control the interface
	   later.
	*/
    if (ioctl(tunnel->tun_fd, TAPGIFNAME, &tunnel->ifr)) {
		perror("ioctl(TAPGIFNAME) failed");
		exit(1);
    }
	tunnel->ifr.ifr_name[IFNAMSIZ-1] = 0
#endif

    /* Set flags on new interface: requires a dummy socket for
	   ioctl */
    int tmp_fd;
    if ((tmp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Failed to create tunnel control socket");
		exit(1);
    }

    tunnel->ifr.ifr_flags |= IFF_UP;
    tunnel->ifr.ifr_flags |= IFF_RUNNING;

    if (ioctl(tmp_fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
		fprintf(stderr, "Failed to set interface flags on %s tunnel interface: %s", tunnel->name, strerror(errno));
		close(tmp_fd);
		exit(1);
    }

    close(tmp_fd);

    /* and set non-blocking */
    fcntl(tunnel->tun_fd, F_SETFL, O_NONBLOCK);

	if(gVerbose >= 1){
		printf("Opened tunnel '%s' as device '%s'\n", tunnel->name, tunnel->ifr.ifr_name);
	}
	if(gVerbose >= 3) fprintf(stderr, "\t - on socket %d\n", tunnel->tun_fd);
}

void tunnel_close(struct tunnel* t){
#if defined(__FreeBSD__)
	int tmpfd;
    if ((tmpfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("tunnel_close: socket() failed");
    }
	else if (ioctl(tmpfd, SIOCIFDESTROY, t->ifr) < 0) {
	    perror( "ioctl(SIOCIFDESTROY) failed");
	}
	close(tmpfd);
#endif

	close(t->tun_fd);
}

