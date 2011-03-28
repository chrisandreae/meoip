/*
    file:   meoip.c
    Authors: 
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#ifdef __linux__
#include <netinet/ether.h>
#include <linux/if_tun.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#ifdef __FreeBSD__
#include <net/if_tap.h>
#endif
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include "minIni.h"

/* In theory maximum payload that can be handled is 65536, but if we use vectorized
   code with preallocated buffers - it is waste of space, especially for embedded setup.
   So if you want oversized packets - increase MAXPAYLOAD up to 65536 (or a bit less)
   If you choice performance - more vectors, to avoid expensive context switches
*/

#define MAXPAYLOAD (2048)
#define PREALLOCBUF 32
#define MAXRINGBUF  64

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

typedef struct
{
   struct sockaddr_in   daddr;
   int                  id;
   int                  fd;
   struct ifreq		ifr;
   char 		name[65];
}  Tunnel;

struct thr_rx
{
    int raw_socket;
};

struct thr_tx
{
    int raw_socket;
    Tunnel *tunnel;
};

int numtunnels;
Tunnel *tunnels;

void term_handler(int s)
{ 
  int 		fd, i;
  Tunnel	*tunnel;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket() failed");
    exit(-1);
  }

  for(i=0;i<numtunnels;i++)
  {
    tunnel = tunnels + i;

#ifdef __FreeBSD__
    if (ioctl(fd, SIOCIFDESTROY, &tunnel->ifr))
    {
      perror( "ioctl(SIOCIFDESTROY) failed");
    }
#endif
    close(tunnel->fd);
  }

  close(fd);
  exit(0);
}

#ifdef __linux__
int open_tun(Tunnel *tunnel)
{
    int fd;
    
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() failed");
      return 1;
    }
    if ( (tunnel->fd = open("/dev/net/tun",O_RDWR)) < 0)
    {
	perror("open_tun: /dev/net/tun error");
	return 1;
    }

    bzero(&tunnel->ifr, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (tunnel->name[0] != 0)
	strncpy(tunnel->ifr.ifr_name, tunnel->name,IFNAMSIZ);
    else
	strncpy(tunnel->ifr.ifr_name, "eoip%d",IFNAMSIZ);

    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
        close(fd);
        return 1;
    }

/*
    if (ioctl(tunnel->fd, TUNGETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctlg-1");
        close(fd);
        return 1;
    }
*/

    tunnel->ifr.ifr_flags |= IFF_UP;
    tunnel->ifr.ifr_flags |= IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-2");
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

#endif

#ifdef __FreeBSD__

int open_tun(Tunnel *tunnel)
{
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() failed");
      return 1;
    }

    if ((tunnel->fd = open("/dev/tap", O_RDWR)) < 0) 
    {
	perror("open_tun: /dev/tap error");
	return 1;
    }

    bzero(&tunnel->ifr, sizeof(tunnel->ifr));

    if (ioctl(tunnel->fd, TAPGIFNAME, &tunnel->ifr)) 
    {
      perror( "ioctl(TAPGIFNAME) failed");
      close(fd);
      return 1;
    }

    tunnel->ifr.ifr_name[IFNAMSIZ-1] = 0;
    tunnel->ifr.ifr_flags = IFF_UP | IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, &tunnel->ifr)) 
    {
      perror( "ioctl(SIOCSIFFLAGS) failed");
      close(fd);
      return 1;
    }

    close(fd);
    return 0;
}
#endif

void *thr_rx(void *threadid)
{
    unsigned char *rxringbufptr[MAXRINGBUF];
    int rxringpayload[MAXRINGBUF];
    unsigned char *rxringbuffer;
    int rxringbufused = 0;
    unsigned char *ptr;
    int i,ret;
    struct thr_rx *thr_rx_data = (struct thr_rx*)threadid;
    Tunnel *tunnel;
    int raw_socket = thr_rx_data->raw_socket;
    fd_set rfds;
    


    rxringbuffer = malloc(MAXPAYLOAD*MAXRINGBUF);
    if (!rxringbuffer) {
	perror("malloc()");
	exit(1);
    }
    /* Temporary code*/
    for (i=0;i<MAXRINGBUF;i++) {
	rxringbufptr[i] = rxringbuffer+(MAXPAYLOAD*i);
    }

    while(1) {

           FD_ZERO(&rfds);
           FD_SET(raw_socket, &rfds);
           ret = select(raw_socket+1, &rfds, NULL, NULL, NULL);

	    assert(rxringbufused == 0);
	    while (rxringbufused < MAXRINGBUF) {
		rxringpayload[rxringbufused] = read(raw_socket,rxringbufptr[rxringbufused],MAXPAYLOAD);
		if (rxringpayload[rxringbufused] < 0)
		    break;

		if (rxringpayload[rxringbufused] >= 28)
		    rxringbufused++;
	    }

	    if (!rxringbufused)
		continue;

	    do {
		rxringbufused--;
		ptr = rxringbufptr[rxringbufused];
		ret = 0;
		/* TODO: Optimize search of tunnel id */
        	for(i=0;i<numtunnels;i++)
        	{
	    	    tunnel=tunnels + i;		    
            	    if (ptr[26] == (unsigned char )(tunnel->id & 0xFF) && ptr[27] == (unsigned char )(((tunnel->id & 0xFF00) >> 8)))
	    	    {
			ret = write(tunnel->fd,ptr+28,rxringpayload[rxringbufused]-28);
		        break;
	    	    }
		}
		// debug
		//if (ret == 0)
		//    printf("Invalid ID received on gre\n");
	    } while (rxringbufused);
    }
    return(NULL);    
}

void *thr_tx(void *threadid)
{
    struct thr_tx *thr_tx_data = (struct thr_tx*)threadid;
    Tunnel *tunnel = thr_tx_data->tunnel;
    int fd = tunnel->fd;
    int raw_socket = thr_tx_data->raw_socket;
    unsigned char *ip = malloc(MAXPAYLOAD+8); /* 8-byte header of GRE, rest is payload */
    int payloadsz;
    unsigned char *payloadptr = ip+8;
    struct sockaddr_in daddr;
    int ret;
    fd_set rfds;

    bzero(ip,20);

    // GRE info?
    ip[0] = 0x20;
    ip[1] = 0x01;
    ip[2] = 0x64;
    ip[3] = 0x00;

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        ret = select(fd+1, &rfds, NULL, NULL, NULL);

	payloadsz = read(fd,payloadptr,MAXPAYLOAD);
	if (payloadsz < 0)
	    continue;
	ip[4] = (unsigned char)((payloadsz & 0xFF00) >> 8);
	ip[5] = (unsigned char)(payloadsz & 0xFF);

	// tunnel id
	ip[6] = (unsigned char )(tunnel->id & 0xFF);
	ip[7] = (unsigned char )((tunnel->id & 0xFF00) >> 8);

	if(sendto(raw_socket, ip, payloadsz+8, 0,(struct sockaddr *)&tunnel->daddr, (socklen_t)sizeof(daddr)) < 0)
	    perror("send() err");
    }
    return(NULL);    
}

int main(int argc,char **argv)
{
    struct thr_rx thr_rx_data;
    struct thr_tx *thr_tx_data;
    

    int ret, i, sn,rc;
//    struct pollfd pollfd[argc-1];
    Tunnel *tunnel;
    struct sigaction sa;
    struct stat mystat;
    char section[IFNAMSIZ];
    char strbuf[256];
    char *configname;
    char defaultcfgname[] = "/etc/meoip.cfg";
    pthread_t *threads;
    pthread_attr_t attr;
    void *status;

    printf("Mikrotik EoIP %s\n",VERSION);
    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");
    printf("Tip: %s [configfile [bindip]]\n",argv[0]);

    thr_rx_data.raw_socket = socket(PF_INET, SOCK_RAW, 47);


    
    if (argc == 3) {
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, argv[2], (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
	    perror("bind address invalid");
	    exit(-1);
	}
	serv_addr.sin_port = 0;
	if (bind(thr_rx_data.raw_socket, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0)
	{
	    perror("bind error");
	    exit(-1);
	}
    }

    if (argc == 1) {
	configname = defaultcfgname;
    } else {
	configname = argv[1];
    }

    if (stat(configname,&mystat)) {
	    perror("config file error");
	    printf("Filename: %s\n",configname);

	    /* TODO: Check readability */
	    exit(-1);
    }

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	numtunnels++;
     }

    tunnels = malloc(sizeof(Tunnel)*numtunnels);
//    assert(tunnels, "malloc()");
    memset(tunnels,0x0,sizeof(Tunnel)*numtunnels);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	tunnel = tunnels + sn;
	printf("Creating tunnel: %s num %d\n", section,sn);

	if (strlen(section)>64) {
	    printf("Name of tunnel need to be shorter than 64 symbols\n");
	    exit(-1);
	}
	strncpy(tunnel->name,section,64);


	tunnel->daddr.sin_family = AF_INET;
	tunnel->daddr.sin_port = 0;
	if (ini_gets(section,"dst","0.0.0.0",strbuf,sizeof(strbuf),configname) < 1) {
	    printf("Destination for %s not correct\n",section);
	} else {
	    printf("Destination for %s: %s\n",section,strbuf);
	}

    	if (!inet_pton(AF_INET, strbuf, (struct in_addr *)&tunnel->daddr.sin_addr.s_addr))
	{
	    warn("Destination \"%s\" is not correct\n", strbuf);
	    exit(-1);
	}
	bzero(tunnel->daddr.sin_zero, sizeof(tunnel->daddr.sin_zero));
	tunnel->id = (int)ini_getl(section,"id",0,configname);
	/* TODO: What is max value of tunnel? */
	if (tunnel->id == 0 || tunnel->id > 65536) {
	    warn("ID of \"%d\" is not correct\n", tunnel->id);
	    exit(-1);
	}

     }
    

    if (thr_rx_data.raw_socket == -1) {
	perror("raw socket error():");
	exit(-1);
    }
    fcntl(thr_rx_data.raw_socket, F_SETFL, O_NONBLOCK);



    for(i=0;i<numtunnels;i++)
    {
      tunnel = tunnels + i;

      if ( open_tun(tunnel) ) {
        exit(-1);
      }
    }


    bzero(&sa, sizeof(sa));
    sa.sa_handler = term_handler;
    sigaction( SIGTERM , &sa, 0);
    sigaction( SIGINT , &sa, 0);

    threads = malloc(sizeof(pthread_t)*(numtunnels+1));

    /* Fork after creating tunnels, useful for scripts */
    ret = daemon(1,1);


    /* structure of Mikrotik EoIP:
	... IP header ...
	4 byte - GRE info
	2 byte - tunnel id
    */


    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    rc = pthread_create(&threads[0], &attr, thr_rx, (void *)&thr_rx_data);

    for(i=0;i<numtunnels;i++)
    {
      tunnel=tunnels + i;
        fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
	/* Allocate for each thread */
	thr_tx_data = malloc(sizeof(struct thr_tx));
        thr_tx_data->tunnel = tunnel;
        thr_tx_data->raw_socket = thr_rx_data.raw_socket;
        rc = pthread_create(&threads[0], &attr, thr_tx, (void *)thr_tx_data);
    }

    rc = pthread_join(threads[0], &status);

    return(0);
}
