#ifndef __GRE_HOST_H
#define __GRE_HOST_H

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

struct tunnel;

struct tunnel_list {
	struct tunnel** tunnels;
	size_t len;
	size_t count;
};

struct gre_host_list { 
	struct gre_host** hosts; 
	size_t len;
	size_t count; 
};

struct gre_host{
    struct sockaddr_storage addr;
	int addr_len;

	struct sockaddr_storage bind_addr;
	int bind_addr_len;

	int socket_fd;

	struct tunnel_list tunnels;
};

/* Global list of GRE hosts: declared in meoip.c */
extern struct gre_host_list gHosts;

struct gre_host* gre_host_alloc();

int gre_host_compar(const void* _key, const void* _host);

/* is it an error to have two connections to the same dest addr with
 different bind addrs?  No, we may need to make sure our source addr
 is specifically what the other side wants.  However it should be an
 error to have a catch-all on a host and also a specifically bound
 source address, since then both sockets will get the messages. Or we
 just cope with that I guess? (drop as appropriate?) */
int gre_host_check_srcconflict(const void* _key, const void* _host);

/* Print a description of the GRE endpoint to the argument stream.*/
void gre_host_format(const struct gre_host* g, char* const obuf, const int olen);

/* Convenience macro for logging: define a local char array and format
 * the specified gre_host into it if the specified verbosity level
 * matches getVerbosity().
 */
#define GRE_HOST_LOG_STR(NAME, LEVEL, HOST)					\
	char NAME[80];											\
	if(getVerbosity() >= (LEVEL))							\
		gre_host_format((HOST), NAME, sizeof(NAME));

/* Looks up or creates a gre_host in gHosts matching the argument
   addresses.*/
struct gre_host* gre_host_for_addr(const struct sockaddr* dest_addr,
								   size_t dest_addr_len,
								   const struct sockaddr* bind_addr,
								   size_t bind_addr_len);

/* Resolves dest and bind and calls gre_host_for_addr */
struct gre_host* gre_host_for_name(char* dest, char* bind);

/* Adds the provided tunnel to the provided gre_host.  If the host
   already contains a tunnel with the same tunnel id, the argument
   tunnel is not added, freed, and a warning is emitted.  */
struct tunnel* gre_host_add_new_tunnel(struct gre_host* host,
									   struct tunnel* tun);

/* Opens the GRE socket and all tunnels associated with it in
   preparation for read/write */
void gre_host_connect(struct gre_host* host);

/* Closes the GRE socket and all tunnels associated with it */
void gre_host_disconnect(struct gre_host* host);

/* Opens, connects and binds the GRE socket. */
void gre_host_open_socket(struct gre_host* host);

/* Closes the GRE socket */
void gre_host_close_socket(struct gre_host* host);

#endif
