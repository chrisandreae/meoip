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

#include <pcap.h>
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

#define MAXPAYLOAD (65536)
#define TUN_MAX_TRY 50

/*! Assert*/
#define assert(x, f) \
if  (x == NULL) \
  { warn("%s:%d %s: %m", __FILE__, __LINE__, f); exit(1);}



typedef struct
{
   struct sockaddr_in   daddr;
   int                  id;
   int                  fd;
   struct ifreq		ifr;
}  Tunnel;

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
    strncpy(tunnel->ifr.ifr_name, "eoip%d",IFNAMSIZ);
    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
        close(fd);
        return 1;
    }
    if (ioctl(tunnel->fd, TUNGETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctlg-1");
        close(fd);
        return 1;
    }

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

int main(int argc,char **argv)
{
    int raw_socket = socket(PF_INET, SOCK_RAW, 47);
    int payloadsz;
    unsigned char *ip = malloc(MAXPAYLOAD+8); /* 8-byte header of GRE, rest is payload */
    unsigned char *rcv = malloc(MAXPAYLOAD+28); /* Header on receive is larger */
    struct sockaddr_in daddr;
    unsigned char *payloadptr = ip+8;
    int ret, i;
    struct pollfd pollfd[argc-1];
    Tunnel *tunnel;
    struct sigaction sa;

    printf("Mikrotik EoIP %s\n",VERSION);
    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");

    if(argc < 2 || argc > TUN_MAX_TRY ){
        fprintf(stdout,"Usage: %s peerip/tunnelid ...\n",argv[0]);
        return 0;
    }

    numtunnels=argc-1;
    tunnels = malloc(sizeof(Tunnel)*numtunnels);
    assert(tunnels, "malloc()");
    bzero(tunnels,sizeof(Tunnel)*numtunnels);

    {


    for(i=0;i<numtunnels;i++)
    {
      int strln, arg_position=0, j;
      char *s;
      j=0;
      tunnel = tunnels + i;
      strln = strlen(argv[i+1]) + 1;
      s = argv[i+1];
      for(j=0;j<strln;j++)
      {
        if ( *(argv[i+1]+j) == '/' || *(argv[i+1]+j) == 0x00)
        {
          *(argv[i+1]+j) = 0x0;
          arg_position++;
          switch (arg_position)
          {
            case 1:
              tunnel->daddr.sin_family = AF_INET;
              tunnel->daddr.sin_port = 0;
    	      if (!inet_pton(AF_INET, s, (struct in_addr *)&tunnel->daddr.sin_addr.s_addr))
	      {
	        warn("Destination \"%s\" is not correct\n", s);
	        exit(-1);
	      }
	      bzero(tunnel->daddr.sin_zero, sizeof(tunnel->daddr.sin_zero));
              s = argv[i+1]+j+1;
            break;
            case 2:
	      tunnel->id = atoi(s);
	      if ( !tunnel->id )
	      {
                warn("Tunnel id \"%s\" is not correct\n", s);
                exit(-1);
	      }
              s = argv[i+1]+j+1;
            break;
          }
        }
      }
      if (arg_position!=2)
      {
        fprintf(stdout,"Usage: %s peerip/tunnelid ...\n",argv[0]);
        exit(-1);
      }
    }

    }

    if (raw_socket == -1) {
	perror("raw socket error():");
	exit(-1);
    }
    fcntl(raw_socket, F_SETFL, O_NONBLOCK);


    bzero(ip,20);

    daemon(0,1);

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
    sleep(100);

    /* structure of Mikrotik EoIP:
	... IP header ...
	4 byte - GRE info
	2 byte - tunnel id
    */


    // GRE info?
    ip[0] = 0x20;
    ip[1] = 0x01;
    ip[2] = 0x64;
    ip[3] = 0x00;

    //ip[6] = 0xd2;
    //ip[7] = 0x04;



    pollfd[0].fd = raw_socket;
    pollfd[0].events = POLLIN;
    pollfd[0].revents = 0; /* unneccesary? */

    for(i=0;i<numtunnels;i++)
    {
      tunnel=tunnels + i;
      fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
      pollfd[i+1].fd = tunnel->fd;
      pollfd[i+1].events = POLLIN;
      pollfd[i+1].revents = 0; /* unneccesary? */
    }

    while ((ret = poll(pollfd,numtunnels+1,-1)) >= 0) {
	if (pollfd[0].revents) {
	    /* TODO: verify tunnel id */
	    payloadsz = read(raw_socket,rcv,MAXPAYLOAD);
	    if (payloadsz < 28)
		continue;

            for(i=0;i<numtunnels;i++)
            {
	      tunnel=tunnels + i;
              /* TODO: verify tunnel id */
              if (rcv[26] == (unsigned char )(tunnel->id & 0xFF) && rcv[27] == (unsigned char )(((tunnel->id & 0xFF00) >> 8)))
	      {
		if (payloadsz<0)
		    break;
		if (payloadsz>8) {
		    write(tunnel->fd,rcv+28,payloadsz-28);
		}
		break;
	      }
	    }
	    continue;
	}


        for(i=0;i<numtunnels;i++)
        {
          tunnel=tunnels + i;

	  if (pollfd[i+1].revents)
	  {
	    pollfd[i+1].revents=0;
	    payloadsz = read(tunnel->fd,payloadptr,MAXPAYLOAD);
	    if (payloadsz < 0)
		break;
	    ip[4] = (unsigned char)(payloadsz & 0xFF00) << 8;
	    ip[5] = (unsigned char)(payloadsz & 0xFF);

	    // tunnel id
	    ip[6] = (unsigned char )(tunnel->id & 0xFF);
	    ip[7] = (unsigned char )(((tunnel->id & 0xFF00) >> 8));

	    if(sendto(raw_socket, ip, payloadsz+8, 0,(struct sockaddr *)&tunnel->daddr, (socklen_t)sizeof(daddr)) < 0)
		perror("send() err");
	    break;
	  }
	}

    }
    return(0);
}
