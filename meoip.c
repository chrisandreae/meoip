/*
    file:   meoip.c
    Author: Denys Fedoryshchenko aka NuclearCat <nuclearcat@nuclearcat.com>

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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>


#define MAXPAYLOAD (65536)

int main(int argc,char **argv)
{ 
    int raw_socket = socket(PF_INET, SOCK_RAW, 47);
    int payloadsz;
    unsigned char *ip = malloc(MAXPAYLOAD+8); /* 8-byte header of GRE, rest is payload */
    unsigned char *rcv = malloc(MAXPAYLOAD+28); /* Header on receive is larger */
    struct sockaddr_in daddr;    
    unsigned char *payloadptr = ip+8;
    int fd,ret;
    struct ifreq ifr;
    struct pollfd pollfd[2];
    int tunnelid;
    char devname[256];

    printf("Mikrotik EoIP %s\n",VERSION);
    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");

    if(argc < 2){ 
        fprintf(stdout,"Usage: %s tunnelid peerip\n",argv[0]);
        return 0;
    }
    tunnelid = atoi(argv[1]);

    if (raw_socket == -1) {
	perror("raw socket error():");
	exit(-1);
    }


    daddr.sin_family = AF_INET;
    daddr.sin_port = 0;
    if (!inet_pton(AF_INET, argv[2], (struct in_addr *)&daddr.sin_addr.s_addr))
    {
	printf("Destination is not correct\n");
	exit(-1);
    }
    memset(daddr.sin_zero, 0, sizeof(daddr.sin_zero));

    memset(ip,0x0,20);

    /* Tun */
    if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) 
	perror("open");

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    strncpy(ifr.ifr_name, "v%d",IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
	perror("ioctl-1");
	exit(-1);
    }

    if (ioctl(fd, TUNGETIFF, (void *)&ifr) < 0) {
	perror("ioctlg-1");
	exit(-1);
    }
    strncpy(devname,ifr.ifr_name,256);


    ifr.ifr_flags |= IFF_UP;
    ifr.ifr_flags |= IFF_RUNNING;
    strncpy(ifr.ifr_name, devname,IFNAMSIZ);
    if (ioctl(raw_socket, SIOCSIFFLAGS, (void *)&ifr) < 0) {
	perror("ioctl-2");
	exit(-1);
    }


//    memset(&ifr, 0, sizeof(ifr));
//    ifr.ifr_mtu = 1492;
//    strncpy(ifr.ifr_name, devname,IFNAMSIZ);
//    if (ioctl(raw_socket, SIOCSIFMTU, (void *)&ifr) < 0) {
//	perror("ioctl-3");
//	exit(-1);
//    }



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

    // tunnel id
    printf("Peer %s TunnelID %d\n",argv[2],tunnelid);
    ip[6] = (unsigned char )(tunnelid & 0xFF);
    ip[7] = (unsigned char )(((tunnelid & 0xFF00) >> 8));

    //ip[6] = 0xd2;
    //ip[7] = 0x04;

    pollfd[0].fd = fd;
    pollfd[0].events = POLLIN;
    pollfd[0].revents = 0; /* unneccesary? */

    pollfd[1].fd = raw_socket;
    pollfd[1].events = POLLIN;
    pollfd[1].revents = 0; /* unneccesary? */

    daemon(0,0);

    while ((ret = poll(pollfd,2,-1)) >= 0) {
	if (pollfd[0].revents) {
	    pollfd[0].revents=0;
	    payloadsz = read(fd,payloadptr,MAXPAYLOAD);
	    if (payloadsz < 0)
		break;
	    ip[4] = (unsigned char)(payloadsz & 0xFF00) << 8;
	    ip[5] = (unsigned char)(payloadsz & 0xFF);
	    if(sendto(raw_socket, ip, payloadsz+8, 0,(struct sockaddr *)&daddr, (socklen_t)sizeof(daddr)) < 0)
		perror("send() err");	
	}

	if (pollfd[1].revents) {
	    /* TODO: verify tunnel id */
	    payloadsz = read(raw_socket,rcv,MAXPAYLOAD);
	    if (payloadsz < 28)
		continue;
	    if (rcv[26] == (unsigned char )(tunnelid & 0xFF) && rcv[27] == (unsigned char )(((tunnelid & 0xFF00) >> 8))) {
		/* TODO: verify tunnel id */
		
		if (payloadsz<0)
		    break;
		if (payloadsz>8) {
		    write(fd,rcv+28,payloadsz-28);
		}
	    }
	}
    }
    return(0);
}
