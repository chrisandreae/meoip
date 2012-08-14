/*
    file:   meoip.c

    Authors:
    MEoIP2 fork: Chris Andreae <chris (at) andreae.gen.nz>
    Linux initial code: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>
    FreeBSD support: Daniil Kharun <harunaga (at) harunaga.ru>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*/
#ifndef __UCLIBC__
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/in.h>

#include "minIni.h"
#include "config.h"

#include "gre_host.h"
#include "tunnel.h"
#include "logging.h"

int gShuttingDown = 0;
struct gre_host_list gHosts = {0};

/* 
 * Maximum size of tunneled frame permitted by eoip protocol is 65535
 * (uint16 size field). However, an ethernet frame is extremely
 * unlikely to be this large: even jumbo frames are only 9000 bytes.
 */
#define MAXPAYLOAD 9000

/* RouterOS eoip protocol is GRE with protocol=0x6400, key=1, version
   = 1, all other flags 0. 32 bit key is composed of 16 bit tunnelled
   frame size (network order) and 16-bit tunnel ID (reverse network
   orderx(!?))
  */
#define MIKROTIK_GRE_PROTO_ID 0x6400
#define GRE_FLAG_KEY (1<<13)  /* bit 3 */
#define GRE_FLAG_VERSION1 (1) /* bit 16 */

#define swap_bytes(x) ((((x) & 0xFF00) >> 8) | (((x) & 0xFF) << 8))

struct proto_hdr{
    uint16_t gre_flags;
	uint16_t gre_protocol;
    uint16_t data_size;
    uint16_t tunnel_id;
} __attribute__((packed));

struct recv_hdr{
    uint8_t ip[20];
    struct proto_hdr hdr;
} __attribute__((packed));


/* inlined bsearch (from glibc) to minimise lookup work each frame.*/
static inline const struct tunnel* tunnel_bsearch (const struct gre_host* h, const int tunnel_id) {
	struct tunnel** const base = h->tunnels.tunnels;
	const size_t nmemb = h->tunnels.count;

	size_t l, u, idx;
	const struct tunnel* p;
	int comparison;

	l = 0;
	u = nmemb;
	while (l < u) {
		idx = (l + u) / 2;
		p = base[idx];
		comparison = tunnel_id - p->id;
		if (comparison < 0)
			u = idx;
		else if (comparison > 0)
			l = idx + 1;
		else
			return p;
	}

	return NULL;
}

void *gre_host_transact(void* _host) {
	const struct gre_host * const host = (const struct gre_host * const) _host;

	{
		GRE_HOST_LOG_STR(host_str, VERBOSE, host);
		log_msg(VERBOSE, "Started gre_host_transact thread for %s\n", host_str);
	}

	const int socket_fd = host->socket_fd;
    const int gre_proto = htons(MIKROTIK_GRE_PROTO_ID);

    uint8_t * const buf = malloc(MAXPAYLOAD);

    fd_set rfds;

    while(1) {
		/* block until we can read */
		FD_ZERO(&rfds);
		FD_SET(socket_fd, &rfds);
		select(socket_fd+1, &rfds, NULL, NULL, NULL);

		/*
		  We want to pump from the OS read buffer to the OS write
		  buffer as fast as possible. We don't want to introduce
		  bufferbloat by adding an extra buffer to the system, so if we
		  can't write something that we read we simply drop it and
		  continue.
		*/
		while(1) {
			int readsz = recv(socket_fd, buf, MAXPAYLOAD, 0);
			if(readsz == -1) {
				if(errno == EAGAIN) break;
				else{
					if(gShuttingDown) return NULL;
					log_msg(VERBOSE, "GRE receive error: %s\n", strerror(errno));
					break;
				}
			}
			else if(readsz == 0) {
				log_msg(VERBOSE, "Impossible, read zero bytes from raw socket\n");
				break;
			}
			else if(readsz < sizeof(struct recv_hdr)){
				log_msg(VERBOSE, "Bad GRE data: smaller than struct recv_hdr (%d bytes)\n", readsz);
				continue;
			}

			struct proto_hdr* hdr = &((struct recv_hdr*) buf)->hdr;
			if(hdr->gre_protocol != gre_proto) {
				log_msg(DEBUG, "Read GRE datagram with unexpected protocol: 0x%x, ignoring\n", ntohs(hdr->gre_protocol));
				continue;
			}
			unsigned short datagram_size = ntohs(hdr->data_size);
			if(datagram_size + sizeof(struct recv_hdr) != readsz) {
				log_msg(VERBOSE, "Read %d bytes from GRE but header claimed it should be %zu (%hu+%zu) bytes: discarding\n",
					readsz, datagram_size + sizeof(struct recv_hdr), datagram_size, sizeof(struct recv_hdr));
				continue;
			}

			/* tunnel id is (for unknown mikrotik reasons)
			   little-endian (*opposite* to network order) */
			unsigned short tunnel_id = ntohs(hdr->tunnel_id);
			tunnel_id = swap_bytes(tunnel_id);

			/* look up the tunnel that corresponds to tunnel_id */
			const struct tunnel* tun = tunnel_bsearch(host, tunnel_id);
			if(tun == NULL){
				GRE_HOST_LOG_STR(host_str, DEBUG, host);
				log_msg(DEBUG, "Unmatched tunnel id %d from host %s\n", tunnel_id, host_str);
				continue;
			}

#ifndef NDEBUG
			{
				GRE_HOST_LOG_STR(host_str, PACKETS, host);
				log_msg(PACKETS, "%s => %s\n", host_str, tun->name);
			}
#endif

			int r = write(tun->tun_fd, buf + sizeof(struct recv_hdr), readsz - sizeof(struct recv_hdr));
			if(r == -1) {
				if(errno == EAGAIN) {
					break;
				}
				else{
					log_msg(NORMAL, "Couldn't write to tunnel device %s: %s\n", tun->name, strerror(errno));
				}
			}
		}
    }
    return 0;
}

void *tunnel_transact(void *_tunnel) {
    const struct tunnel * const tunnel = (const struct tunnel* const)_tunnel;
	
	log_msg(VERBOSE, "Started tunnel_transact thread for %s (in host %p)\n", tunnel->name, tunnel->dest);

    const int fd = tunnel->tun_fd;
    const int raw_socket = tunnel->dest->socket_fd;

    unsigned char * const buf = malloc(MAXPAYLOAD + sizeof(struct proto_hdr));
    struct proto_hdr * const hdr = (struct proto_hdr*) buf;
    unsigned char * const dataptr = buf + sizeof(struct proto_hdr);

    int ret;
    fd_set rfds;

    /* initialize protocol header */
    memset(buf, 0x0, sizeof(struct proto_hdr));

	hdr->gre_flags    = htons(GRE_FLAG_KEY | GRE_FLAG_VERSION1);
    hdr->gre_protocol = htons(MIKROTIK_GRE_PROTO_ID);
    hdr->tunnel_id    = htons(tunnel->id); 
    hdr->tunnel_id    = swap_bytes(hdr->tunnel_id); /* tunnel id is little-endian: opposite to network order */

    while(1) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		ret = select(fd+1, &rfds, NULL, NULL, NULL);

		while(1) {
			int readsz = read(fd, dataptr, MAXPAYLOAD);
			if(readsz == -1) {
				if(errno == EAGAIN) break;
				else{
					if(gShuttingDown) return NULL;
					log_msg(VERBOSE, "TAP device receive error: %s\n", strerror(errno));
					break;
				}
			}
			else if(readsz == 0) {
				log_msg(VERBOSE, "impossible, read nothing from TAP device: %s\n", strerror(errno));
				break;
			}
			hdr->data_size = htons(readsz);

#ifndef NDEBUG
			{
				GRE_HOST_LOG_STR(dest_str, PACKETS, tunnel->dest);
				log_msg(PACKETS, "%s => %s\n", tunnel->name, dest_str);
			}
#endif

			ret = send(raw_socket, buf, readsz + sizeof(struct proto_hdr), 0);
			if(ret == -1) {
				if(errno == EAGAIN){
					/* Silently drop frame, buffer is full. */
					break;
				}
				else{
					log_msg(VERBOSE, "Error writing to raw socket (%d): %s\n", raw_socket, strerror(errno));
					break;
				}
			}
		}
    }
    return(NULL);
}

void add_new_tunnel(char* name, char* dest, char* bind, unsigned short tunnel_id) {
	struct gre_host* host = gre_host_for_name(dest, bind);
	struct tunnel* tun = tunnel_new(name, tunnel_id, host);

	gre_host_add_new_tunnel(host, tun);
}

/* take and parse target host argument */
void load_tunnel_from_argument(const char* arg) {
	char* buf;
	asprintf(&buf, "%s", arg);
	char* next = buf;

	char* name = next;
	next = index(next, '/');
	if(next == NULL){
		log_msg(NORMAL, "Failed to parse tunnel specifier \"%s\" (no host found)\n", arg);
		exit(1);
	}
	*next++ = '\0';

	char* host = next;
	next = index(next, '/');
	if(next == NULL){
		log_msg(NORMAL, "Failed to parse tunnel specifier \"%s\" (no id found)\n", arg);
		exit(1);
	}
	*next++ = '\0';

	char* id_s = next;
	char* ep;
	int id = strtol(id_s, &ep, 10);
	if(*ep != '\0'){
		log_msg(NORMAL, "Failed to parse tunnel specifier \"%s\": bad tunnel id \"%s\"\n", arg, id_s);
		exit(1);
	}

    if (id < 0 || id > 0xffff) {
		log_msg(NORMAL, "ID \"%d\" of tunnel %s is invalid\n", id, name);
		exit(1);
    }

	add_new_tunnel(name, host, NULL, (unsigned short) id);
	free(buf);
}

void load_tunnels_from_config(const char* configname) {
    struct stat mystat;
    if (stat(configname, &mystat)) {
		log_msg(NORMAL, "Couldn't open config file \"%s\": %s\n", configname, strerror(errno));
		exit(1);
    }

    char sectionname[IFNAMSIZ];
	int sn;
    for (sn = 0; ini_getsection(sn, sectionname, sizeof(sectionname), configname) > 0; sn++) {
		char dest[256];
		char bind[256];

		/* read id */
        int id = (int) ini_getl(sectionname,"id",-1,configname);
		if(id == -1){
			log_msg(NORMAL, "Required field 'id' missing for tunnel %s\n", sectionname);
			exit(1);
		}

		/* read destination */
		if (ini_gets(sectionname, "dst", "", dest, sizeof(dest), configname) < 1) {
			log_msg(NORMAL, "Required field 'dst' missing for tunnel %s\n", sectionname);
			exit(1);
		}

		/* read source */
		ini_gets(sectionname, "bind", "", bind, sizeof(bind), configname);

		log_msg(VERBOSE, "Creating tunnel: name=%s dst=%s id=%d", sectionname, dest, id);
		if(bind[0] != '\0'){
			log_msg(VERBOSE, " src=%s", bind);
		}
		log_msg(VERBOSE, "\n");

		add_new_tunnel(sectionname, dest, bind, id);
    }
}

void open_connections(){
	int i;
	for(i = 0; i < gHosts.count; ++i){
		struct gre_host* host = gHosts.hosts[i];
		gre_host_connect(host);
	}
}

void close_connections(){
	/* call only once, even if fired by multiple signal handlers */
	static int closed = 0;
	if(closed) return;
	closed = 1;

	log_msg(VERBOSE, "Shutting down connections\n");

	int i;
	for(i = 0; i < gHosts.count; ++i){
		struct gre_host* host = gHosts.hosts[i];
		gre_host_disconnect(host);
	}
}

void term_handler(int s)
{
	gShuttingDown = 1;
	close_connections();
	exit(0);
}

void printusage(){
    fprintf(stderr, "Mikrotik EoIP %s\n",PACKAGE_VERSION);
    fprintf(stderr, "https://github.com/chrisandreae/meoip.git\n");
    fprintf(stderr, "Usage: meoip [OPTIONS]\n");
    fprintf(stderr, " -h\t\tPrint this help message.\n");
    fprintf(stderr, " -F\t\tRun in foreground.\n");
    fprintf(stderr, " -v\t\tVerbose\n");
    fprintf(stderr, " -f configfile\tConfig file path\n");
    fprintf(stderr, " -t name/host/id\tSpecify tunnel on command line\n");
    fprintf(stderr, " -p pidfile\tOutput to alternate pid file\n");
}

int main(int argc,char **argv)
{
    /* defaults */
    int background   = 1;
    char *pidfile    = NULL;

	int configured = 0;

    const char* defaultcfgname = "/etc/meoip.cfg";

    /* parse options */
    char opt;
    while((opt = getopt(argc, argv, "hFvf:t:p:b:")) != -1) {
		switch(opt) {
		case 'h':
			printusage();
			exit(0);
		case 'F': 
			background = 0;
			break;
		case 'v':
			setVerbosity(getVerbosity() + 1);
			break;
		case 'p':
			if(pidfile){
				log_msg(NORMAL, "-<pidfile> p may be specified only once.\n");
				exit(1);
			}
			asprintf(&pidfile, "%s", optarg);
			break;
		case 't':
			load_tunnel_from_argument(optarg);
			configured = 1;
			break;
		case 'f':
			load_tunnels_from_config(optarg);
			configured = 1;
			break;
		default:
			printusage();
			exit(1);
		}
    }
    
	/* if not configured, try default config file */
	if(!configured){
		load_tunnels_from_config(defaultcfgname);
	}
	/* open sockets and tunnel devices */
    open_connections();

    /* register signal handler */
    struct sigaction sa;
    memset(&sa, 0x0, sizeof(sa));
    sa.sa_handler = term_handler;
    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGINT,  &sa, 0);


    /* Fork after creating tunnels, useful for scripts */
    if(background) {
		int ret = daemon(1, 1);
		if(ret != 0) {
			log_msg(NORMAL, "Daemon failed: %s\n", strerror(errno));
			exit(ret);
		}
    }

    /* output pid file */
	{
		if(!pidfile) {
			int ret = asprintf(&pidfile, "/var/run/meoip");
			if(ret == -1) {
				log_msg(NORMAL, "Error allocating pid file name: %s\n", strerror(errno));
				exit(1);
			}
		}

		FILE* mfd = fopen(pidfile, "w");
		free(pidfile); /* always heap-allocated */
		if(mfd == NULL) {
			log_msg(NORMAL, "Error opening pid file %s: %s\n", pidfile, strerror(errno));
		}
		fprintf(mfd,"%d",getpid());
		fclose(mfd);
	}

    /* set up threads */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	
	int i, j, rc;
	pthread_t thread;
	for(i = 0; i < gHosts.count; ++i){
		struct gre_host* host = gHosts.hosts[i];
		rc = pthread_create(&thread, &attr, gre_host_transact, (void*) host);
		if(rc != 0){
			GRE_HOST_LOG_STR(host_str, NORMAL, host);
			log_msg(NORMAL, "Couldn't start transmit thread for host %s\n", host_str);
			exit(1);
		}
		for(j = 0; j < host->tunnels.count; ++j){
			rc = pthread_create(&thread, &attr, tunnel_transact, (void*) host->tunnels.tunnels[j]);
			if(rc != 0){
				log_msg(NORMAL, "Couldn't start receive thread for tunnel %s\n", host->tunnels.tunnels[j]->name);
				exit(1);
			}
		}
	}
	pthread_join(thread, 0); /* join the last thread to be created (as
								no threads will ever exit, effectively
								block forever) */
	exit(0);
}
