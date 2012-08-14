#include "tunnel.h"
#include "gre_host.h"
#include "logging.h"

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

struct tunnel* tunnel_new(char* name, unsigned short tunnel_id, struct gre_host* host) {

	/* Create and populate a new tunnel */
	struct tunnel* tun = tunnel_alloc();

	tun->dest = host;

	strncpy(tun->name, name, sizeof(tun->name));
	tun->name[sizeof(tun->name) - 1] = '\0';

	tun->id = tunnel_id;

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
		log_msg(PACKETS, "Attempting to open device %s: ", path);
		if((tunnel->tun_fd = open(path, O_RDWR)) > 0){
			/* success - save the name in the IFR so we can bring it
			   up */
			log_msg(PACKETS, "Success (socket %d)\n", tunnel->tun_fd);
			sprintf(tunnel->ifr.ifr_name, "tap%d", tapdev);
			break;
		}
		else{
			log_msg(PACKETS, "Failed\n");
		}
	}
	if(tunnel->tun_fd < 0){
		log_msg(NORMAL, "open_tun: error opening any /dev/tap* device: %s\n", strerror(errno));
		exit(1);
	}
#else
	/* On other platforms, we have a generic device to open. */
	if ((tunnel->tun_fd = open(TUNNEL_DEV, O_RDWR)) < 0) {
		log_msg(NORMAL, "open_tun: %s error: %s\n", TUNNEL_DEV, strerror(errno));
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
		log_msg(NORMAL, "Failed to create tunnel interface: %s\n", strerror(errno));
		exit(1);
	}
#elif defined(__FreeBSD__)
	/* When creating a device with /dev/tap on BSD, we don't get to
	   set the name. We can find out what it actually is called with
	   the TAPGIFNAME ioctl, and use that to control the interface
	   later.
	*/
	if (ioctl(tunnel->tun_fd, TAPGIFNAME, &tunnel->ifr)) {
		log_msg(NORMAL, "ioctl(TAPGIFNAME) failed: %s\n", strerror(errno));
		exit(1);
	}
	tunnel->ifr.ifr_name[IFNAMSIZ-1] = 0
#endif

	/* Set flags on new interface: requires a dummy socket for
	   ioctl */
	int tmp_fd;
	if ((tmp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		log_msg(NORMAL, "Failed to create tunnel control socket: %s\n", strerror(errno));
		exit(1);
	}

	tunnel->ifr.ifr_flags |= IFF_UP;
	tunnel->ifr.ifr_flags |= IFF_RUNNING;

	if (ioctl(tmp_fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
		log_msg(NORMAL, "Failed to set interface flags on %s tunnel interface: %s\n", tunnel->name, strerror(errno));
		close(tmp_fd);
		exit(1);
	}

	close(tmp_fd);

	/* and set non-blocking */
	fcntl(tunnel->tun_fd, F_SETFL, O_NONBLOCK);

	log_msg(VERBOSE, "Opened tunnel '%s' as device '%s'\n", tunnel->name, tunnel->ifr.ifr_name);

	log_msg(DEBUG, "\t - on socket %d\n", tunnel->tun_fd);
}

void tunnel_close(struct tunnel* t){
#if defined(__FreeBSD__)
	int tmpfd;
	if ((tmpfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		log_msg(DEBUG, "tunnel_close - socket() failed: %s\n", strerror(errno));
	}
	else{
		if (ioctl(tmpfd, SIOCIFDESTROY, t->ifr) < 0) {
			log_msg(DEBUG, "tunnel_close - ioctl(SIOCIFDESTROY) failed: %s\n", strerror(errno));
		}
		close(tmpfd);
	}
#endif

	close(t->tun_fd);
}
