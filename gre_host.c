#include "gre_host.h"
#include "tunnel.h"
#include "logging.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct gre_host* gre_host_alloc(){
	struct gre_host* n = malloc(sizeof(struct gre_host));
	memset(n, 0x0, sizeof(struct gre_host));
	return n;
}

int gre_host_compar(const void* _key, const void* _host){
	struct gre_host* key  = *(struct gre_host**) _key;
	struct gre_host* host = *(struct gre_host**) _host;
	if(key->addr_len != host->addr_len)
		return key->addr_len - host->addr_len;

	int ac = memcmp(&key->addr, &host->addr, host->addr_len);
	if(ac != 0) return ac;

	if(key->bind_addr_len != host->bind_addr_len)
		return key->bind_addr_len - host->bind_addr_len;

	if(key->bind_addr_len == 0) /* no bind addr to compare */
		return 0;

	return memcmp(&key->bind_addr, &host->bind_addr, host->bind_addr_len);
}

int addr_is_wildcard(const struct sockaddr* addr, size_t addr_len){
	if(addr_len == 0) return 1;

	switch(addr->sa_family){
	case AF_INET:
		return ((struct sockaddr_in*)addr)->sin_addr.s_addr == INADDR_ANY;
	case AF_INET6:
		return 0 == memcmp(&(((struct sockaddr_in6*)addr)->sin6_addr), &in6addr_any, sizeof(struct in6_addr));
	default:
		log_msg(NORMAL, "addr_is_wildcard() - unknown address family %d\n", addr->sa_family);
		exit(1);
	}
	return 0;
}

/* is it an error to have two connections to the same dest addr with
	different bind addrs?  No, we may need to make sure our source
	addr is specifically what the other side wants.  However it should
	be an error to have a catch-all on a host and also a specifically
	bound source address, since then both sockets will get the
	messages.  or we just cope with that I guess? (drop as
	appropriate?)
 */
int gre_host_check_srcconflict(const void* _key, const void* _host){
	struct gre_host* key  = *(struct gre_host**) _key;
	struct gre_host* host = *(struct gre_host**) _host;

	if(key->addr_len != host->addr_len)
		return 1;

	if(0 != memcmp(&key->addr, &host->addr, host->addr_len))
		return 1;

	int key_wc  = addr_is_wildcard((struct sockaddr*)&key->bind_addr,  key->bind_addr_len);
	int host_wc = addr_is_wildcard((struct sockaddr*)&host->bind_addr, host->bind_addr_len);

	return key_wc == host_wc; /* returns 0 if not equal => conflict */
}

void gre_host_format(const struct gre_host* g, char * const obuf, const int olen){
	char abuf[64], bbuf[64];
	getnameinfo((struct sockaddr*)&g->addr, g->addr_len, abuf, sizeof(abuf), 0, 0, NI_NUMERICHOST);
	if(g->bind_addr_len){
		getnameinfo((struct sockaddr*)&g->bind_addr, g->bind_addr_len, bbuf, sizeof(bbuf), 0, 0, NI_NUMERICHOST);
	}
	else{
		sprintf(bbuf, "<any>");
	}
	if(getVerbosity() >= DEBUG){
		snprintf(obuf, olen, "[%s -> %s]@%p", bbuf, abuf, g);
	}
	else{
		snprintf(obuf, olen, "[%s -> %s]", bbuf, abuf);
	}
}


struct gre_host* gre_host_for_addr(const struct sockaddr* dest_addr, size_t dest_addr_len,
								   const struct sockaddr* bind_addr, size_t bind_addr_len){
	struct gre_host* g = gre_host_alloc();
	memcpy(&g->addr, dest_addr, dest_addr_len);
	g->addr_len = dest_addr_len;

	if(bind_addr_len){
		memcpy(&g->bind_addr, bind_addr, bind_addr_len);
		g->bind_addr_len = bind_addr_len;
	}

	/* Restriction: we don't permit multiple hosts with the same
	   destination and both bound and unbound source addresses, as
	   that would result in the same traffic going to both hosts
	*/
	struct gre_host** srcConflict = (struct gre_host**) lfind(&g, gHosts.hosts, &gHosts.count,
										 sizeof(struct gre_host*), gre_host_check_srcconflict);
	if(srcConflict != NULL){
		log_msg(NORMAL, "Tunnel conflict: must not have two tunnels to the same destination"
				" where one is bound to a local address and the other is not.\n");
		exit(1);
	}

	/* make space if necessary */
	if(gHosts.count == gHosts.len){
		gHosts.len = (gHosts.len * 2 + 1);
		gHosts.hosts = realloc(gHosts.hosts, sizeof(struct gre_host*) * gHosts.len);
	}
	/* lsearch appends if not found, returns entry. */
	struct gre_host* loc = *(struct gre_host**) lsearch(&g, gHosts.hosts, &gHosts.count, sizeof(struct gre_host*), gre_host_compar);

	{
		GRE_HOST_LOG_STR(loc_str, DEBUG, loc);
		log_msg(DEBUG, "Adding to %s GRE host: %s\n", loc == g ? "new" : "existing", loc_str);
	}

	/* if already present, free */
	if(loc != g) free(g);


	return loc;
}

struct gre_host* gre_host_for_name(char* dest, char* bind){
	struct addrinfo hints;

	/* look up the bind address, if specified */
	struct addrinfo* bind_addrinfo = 0;
	struct sockaddr* bind_addr = 0;
	int bind_addrlen = 0;
	if(bind && bind[0] != '\0'){
		memset(&hints, 0x0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		int r = getaddrinfo(bind, NULL, &hints, &bind_addrinfo);
		if(r != 0){
			log_msg(NORMAL, "Address lookup of \"%s\" failed - not a valid IP address? (%s)\n",
					bind,
					r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
			exit(1);
		}
		bind_addr = bind_addrinfo->ai_addr;
		bind_addrlen = bind_addrinfo->ai_addrlen;
	}

	/* Look up the destination address */
	memset(&hints, 0x0, sizeof(hints));
	hints.ai_socktype = AF_INET; /* ipv4 only */
	struct addrinfo* res;

	/* Assume that the first struct returned is appropriate, as we're
	   asking for ipv4 only (TODO: ipv6) */
	int r = getaddrinfo(dest, NULL, &hints, &res);
	if(r != 0) {
		log_msg(NORMAL, "DNS resolution of \"%s\" failed: %s\n",
				dest,
				r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		exit(1);
	}

	/* look up the host by address and return */
	struct gre_host* host = gre_host_for_addr(res->ai_addr, res->ai_addrlen,
											  bind_addr, bind_addrlen);
	freeaddrinfo(res);
	if(bind_addrinfo) freeaddrinfo(bind_addrinfo);
	return host;
}

struct tunnel* gre_host_add_new_tunnel(struct gre_host* host, struct tunnel* tun){
	if(host->tunnels.count == host->tunnels.len){
		host->tunnels.len = host->tunnels.len * 2 + 1;
		host->tunnels.tunnels = realloc(host->tunnels.tunnels,
										sizeof(struct tunnel*) * host->tunnels.len);
	}
	struct tunnel* t = *(struct tunnel**) lsearch(&tun, host->tunnels.tunnels, &host->tunnels.count,
												sizeof(struct tunnel*), tunnel_compar);
	if(t != tun){
		GRE_HOST_LOG_STR(host_str, VERBOSE, host);
		log_msg(VERBOSE, "Warning: ignored duplicate tunnel %s (id %d, same as %s) for host %s\n",
			tun->name, t->id, t->name, host_str);
		free(tun);
	}

	{
		GRE_HOST_LOG_STR(host_str, DEBUG, host);
		log_msg(DEBUG, "Added new tunnel %s (id %d) to host %s\n", t->name, t->id, host_str);
	}

	return t;
}

void gre_host_connect(struct gre_host* host){
	int j;

	/* sort for binary search on receive */
	qsort(host->tunnels.tunnels, host->tunnels.count, sizeof(struct tunnel*), tunnel_compar);

	gre_host_open_socket(host);

	for(j = 0; j < host->tunnels.count; ++j){
		tunnel_open(host->tunnels.tunnels[j]);
	}
}

void gre_host_disconnect(struct gre_host* host){
	int j;

	gre_host_close_socket(host);

	for(j = 0; j < host->tunnels.count; ++j){
		tunnel_close(host->tunnels.tunnels[j]);
		free(host->tunnels.tunnels[j]);
	}

	free(host->tunnels.tunnels);
	free(host);
}

/* Create the socket */
void gre_host_open_socket(struct gre_host* host){
	host->socket_fd = socket(host->addr.ss_family, SOCK_RAW, IPPROTO_GRE);

	if(host->socket_fd == -1){
		const char* const err_str = strerror(errno);
		GRE_HOST_LOG_STR(host_str, DEBUG, host);
		log_msg(NORMAL, "Error opening GRE socket for host %s: %s\n", host_str, err_str);
		exit(1);
	}
	else {
		GRE_HOST_LOG_STR(host_str, DEBUG, host);
		log_msg(DEBUG, "Opened raw socket %d for host %s\n", host->socket_fd, host_str);
	}

	/* Do we want to consider setting the buffer sizes to the BDP,
	   remembering that we are a tunnel, and therefore the connections
	   going over us will be independently buffered. Real question is
	   whether adjusting buffers here allows us to usefully employ
	   knowledge about the capacity/rtt of our link.
	*/
	/* int optval=262144; */
	/* if(setsockopt (raw_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof (optval))) */
	/* perror("setsockopt(RCVBUF)"); */
	/* if(setsockopt (raw_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof (optval))) */
	/* perror("setsockopt(SNDBUF)"); */

	if(host->bind_addr_len > 0){
		if(bind(host->socket_fd, (const struct sockaddr*) &host->bind_addr, host->bind_addr_len) == -1){
			const char* const err_str = strerror(errno);
			GRE_HOST_LOG_STR(host_str, DEBUG, host);
			log_msg(NORMAL, "Error binding GRE socket for host %s: %s\n", host_str, err_str);
			exit(1);
		}
	}
	while(connect(host->socket_fd, (const struct sockaddr*) &host->addr, host->addr_len) == -1){
		if(errno == ENETUNREACH){
			log_msg(VERBOSE, "Can't connect() GRE socket - network is not yet available (ENETUNREACH). Waiting 1 second...\n");
			sleep(1);
		}
		else{
			const char* const err_str = strerror(errno);
			GRE_HOST_LOG_STR(host_str, DEBUG, host);
			log_msg(NORMAL, "Error connecting GRE socket for host %s: %s\n", host_str, err_str);
			exit(1);
		}
	}
	if(fcntl(host->socket_fd, F_SETFL, O_NONBLOCK) == -1){
		const char* const err_str = strerror(errno);
		GRE_HOST_LOG_STR(host_str, DEBUG, host);
		log_msg(NORMAL, "Could not set GRE socket non-blocking for host %s: %s\n", host_str, err_str);
		exit(1);
	}
}

void gre_host_close_socket(struct gre_host* host){
	close(host->socket_fd);
	host->socket_fd = 0;
}
