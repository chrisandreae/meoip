/*
    file:   vip.c
    Authors: 
    Linux initial code: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

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
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include "minIni.h"
#include <getopt.h>

#ifdef HAVE_LIBLZO2
#include <lzo/lzo1x.h>
#endif

//#ifdef GCRYPT
//#include <gcrypt.h>
//#define  ADDON 2
//#else
#define  ADDON 0
//#endif

/* In theory maximum payload that can be handled is 65536, but if we use vectorized
   code with preallocated buffers - it is waste of space, especially for embedded setup.
   So if you want oversized packets - increase MAXPAYLOAD up to 65536 (or a bit less)
   If you choice performance - more vectors, to avoid expensive context switches
*/

#define MAXPAYLOAD (4096)
//#define MAXPACKED (1500-200)
//#define MAXPACKED (1700)
//#define PREALLOCBUF 32
#define MAXRINGBUF  64

#define BIT_COMPRESSED 		(1 << 0)
#define BIT_PACKED 		(1 << 1)
#define BIT_SERVICE 		(1 << 2)

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

#ifndef __cacheline_aligned
#define __cacheline_aligned \
__attribute__((__aligned__(SMP_CACHE_BYTES), \
__section__(".data.cacheline_aligned")))
#endif /* __cacheline_aligned */
#define __read_mostly __attribute__((__section__(".data.read_mostly")))

pthread_mutex_t raw_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
   struct sockaddr_in   daddr;
   int                  id;
   int                  fd;
   struct ifreq		ifr;
   char 		name[65];
   struct thr_tx 	*thr_tx_data;
}  Tunnel;

struct thr_rx
{
    int raw_socket;
};

struct thr_tx
{
    int 			raw_socket;
    Tunnel 			*tunnel;
    int 			cpu;
    unsigned int		packdelay;
    int				maxpacked;
    int				compression;
};

/*
struct snd_buf
{
    unsigned char		data[MAXPAYLOAD];
    unsigned int 		size;
    unsigned int		crc;
};
*/


static int numtunnels;
static Tunnel *tunnels;


/*
void error( const char* format, ...) {
    va_list args;
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
    fprintf( stderr, "\n" );
}
*/

static int open_tun(Tunnel *tunnel)
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

    memset(&tunnel->ifr, 0x0, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
    if (tunnel->name[0] != 0)
	strncpy(tunnel->ifr.ifr_name, tunnel->name,IFNAMSIZ);
    else
	strncpy(tunnel->ifr.ifr_name, "vip%d",IFNAMSIZ);

    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
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


static void *thr_rx(void *threadid)
{
    static unsigned char *rxringbufptr[MAXRINGBUF];
    static int rxringpayload[MAXRINGBUF];
    static unsigned char *rxringbuffer;
    static int rxringbufused = 0, rxringconsumed;
    static unsigned char *ptr;
    static int i,ret;
    struct thr_rx *thr_rx_data = (struct thr_rx*)threadid;
    static Tunnel *tunnel;
    int raw_socket = thr_rx_data->raw_socket;
    static unsigned char *decompressed = NULL;
    static unsigned int decompressedsz;
    static fd_set rfds;

    /* 2-byte header of VIP, rest is payload */
    if (posix_memalign((void*)&decompressed, 64, MAXPAYLOAD)) {
	printf("memalign failed\n");
	pthread_exit(0);
    }
    
#ifndef __UCLIBC__
    cpu_set_t cpuset;
    int cpu=0;
    pthread_t thread = pthread_self();


    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n",ret);
    else
	printf("RX thread cpu %d\n",cpu);
#endif
#ifdef HAVE_LIBLZO2
    ret = lzo_init();    
    if (ret != LZO_E_OK) {
	printf("LZO init failed\n");
	exit(1);
    }

//    if (posix_memalign((void **)&wrkmem, 64, LZO1X_1_MEM_COMPRESS))
//	exit(1);

#endif


    rxringbuffer = malloc(MAXPAYLOAD*MAXRINGBUF);

/*    if (posix_memalign((void **)&rxringbuffer, 64, MAXPAYLOAD*MAXRINGBUF))
	exit(1);
*/

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

	    while (rxringbufused < MAXRINGBUF) {
		pthread_mutex_lock(&raw_mutex);
		rxringpayload[rxringbufused] = read(raw_socket,rxringbufptr[rxringbufused],MAXPAYLOAD);
		pthread_mutex_unlock(&raw_mutex);
		
		if (rxringpayload[rxringbufused] < 0)
		    break;

		if (rxringpayload[rxringbufused] >= 2)
		    rxringbufused++;
	    }

	    if (!rxringbufused)
		continue;

	    rxringconsumed=0;
	    do {
		ptr = rxringbufptr[rxringconsumed];
		ret = 0;
		/* TODO: Optimize search of tunnel id */
        	for(i=0;i<numtunnels;i++)
        	{

	    	    tunnel=tunnels + i;		    
            	    if (ptr[20] == (unsigned char )(tunnel->id) )
	    	    {

#ifdef HAVE_LIBLZO2
			if (ptr[21] & BIT_COMPRESSED) {
//			    decompressedsz = MAXPAYLOAD-22-3; /* Lzo note about 3 bytes in asm algos */
			    decompressedsz = MAXPAYLOAD;
			    if (lzo1x_decompress_safe(ptr+22,rxringpayload[rxringconsumed]-22,decompressed,(lzo_uintp)&decompressedsz,NULL) == LZO_E_OK) {
				if (decompressed == NULL) {
				    printf("Please report to developer about this bug\n");
				    //pthread_exit(1);
				}
				memcpy(ptr+22,decompressed,decompressedsz);
				rxringpayload[rxringconsumed] = decompressedsz + 22;
			    } else {				
				perror("lzo feeling bad about your packet\n");\
				break;
				//exit(1);
			    }
			}
			

#else

			if (ptr[21] & BIT_COMPRESSED) {
			    printf("Can't decompress. TODO\n");
			    exit(0);
			}
#endif

			if ((ptr[21] & BIT_PACKED)) {
			    unsigned int offset = 22; /* 20 IP header + 2 byte of tunnel id and bitfield */
			    unsigned short total;

//			    ctr_packed++;				
			    while(1) {				
				total = ntohs(*(uint16_t*)(ptr+offset+2)); /* 2 byte - IP offset to total len */
				
				if ((int)(offset+total)>rxringpayload[rxringconsumed]) {				    
				    printf("invalid offset! %d > %d IP size %d\n",(offset+total),rxringpayload[rxringconsumed],total);				    
				    break;
				}
				pthread_mutex_lock(&raw_mutex);
				ret = write(tunnel->fd,ptr+offset,total);
				pthread_mutex_unlock(&raw_mutex);
				if (ret<0) {
				    perror("tunnel write error #1\n");
				    printf("error details: %d,%d\n",offset,total);
				    break;
				}
				

				offset += total;
				
				/* This is correct, finished processing packed data */
				if ((int)offset == rxringpayload[rxringconsumed])
				    break;
				if ((int)offset > rxringpayload[rxringconsumed]) {
				    printf("invalid offset! %d+%d > %d\n",offset,total,rxringpayload[rxringconsumed]);
				    break;
				}
				
			    }
			} else {
			    pthread_mutex_lock(&raw_mutex);
			    ret = write(tunnel->fd,ptr+22,rxringpayload[rxringconsumed]-22);
			    pthread_mutex_unlock(&raw_mutex);
			    
			    if (ret<0)
			        printf("tunnel write error #2\n");
			}
		        break;
	    	    }
		}

		rxringconsumed++;
	    } while (rxringconsumed < rxringbufused);
	    rxringbufused -= rxringconsumed;
	    if (rxringbufused) {
		memmove(&rxringpayload[0],&rxringpayload[rxringconsumed],rxringbufused);
	    }

    }
    return(NULL);    
}

static void preserve_data (unsigned char *data,int size) {
    

}


/* Reading from tun interface, processing and pushing to raw socket */
static void *thr_tx(void *threadid)
{
    struct thr_tx *thr_tx_data = (struct thr_tx*)threadid;
    Tunnel *tunnel = thr_tx_data->tunnel;
    int fd = tunnel->fd;
    int raw_socket = thr_tx_data->raw_socket;
    unsigned char *ip = malloc(MAXPAYLOAD+2); /* 2-byte header of VIP, rest is payload */
    unsigned char *payloadptr = ip+2;

    unsigned char *prevptr = malloc(MAXPAYLOAD); /* 2-byte header of VIP, rest is payload */
    int prevavail = 0;

    unsigned char *compressed = malloc(MAXPAYLOAD*2); /* 2-byte header of VIP, rest is payload */
#ifdef HAVE_LIBLZO2
    lzo_voidp wrkmem;
#endif
    int payloadsz;
    int compressedsz;
    struct sockaddr_in daddr;
    int ret;


//    unsigned int ctr_uncompressed = 0, ctr_compressed = 0, ctr_packed = 0, ctr_normal = 0;
    fd_set rfds;
    struct timeval timeout;
    unsigned int packdelay = thr_tx_data->packdelay;
    int maxpacked = thr_tx_data->maxpacked;
    int compression = thr_tx_data->compression;
    int multiplier = 1;
#ifndef __UCLIBC__
    int cpu = thr_tx_data->cpu;
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();
//#ifdef GCRYPT
//    /* CTRL_PKT, 2 byte VIP hdr, 2 byte extra, 1476 - 369 checksums */
//    uint32_t cksumbuf[369];
//#endif

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n",ret);
    else
	printf("TX thread(ID %d) set to cpu %d packdelay %d\n",tunnel->id,cpu,packdelay);


#endif


#ifdef HAVE_LIBLZO2
    ret = lzo_init();
    if (ret != LZO_E_OK) {
	printf("LZO init failed\n");
	exit(1);
    }
    wrkmem = (lzo_voidp)malloc(LZO1X_1_MEM_COMPRESS);
#endif

    memset(ip,0x0,20);

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        ret = select(fd+1, &rfds, NULL, NULL, NULL);

	// tunnel id
	ip[0] = (unsigned char )(tunnel->id & 0xFF);	
	ip[1] = 0; 

	if (!prevavail) {
	    pthread_mutex_lock(&raw_mutex);
	    payloadsz = read(fd,payloadptr,MAXPAYLOAD);
	    pthread_mutex_unlock(&raw_mutex);
	    
	    if (payloadsz < 0)
		continue;

	    unsigned short total = ntohs(*(uint16_t*)(payloadptr+2));
	    if (total != payloadsz)
		printf("t %d p %d\n",total,payloadsz);

	} else {
	    payloadsz = prevavail;
	    memcpy(payloadptr,prevptr,prevavail);
	    prevavail = 0;
	}

	/* If we are fragmented anyway, try to increase second packet size
	    so average packet size will be higher	    
	*/
	if (payloadsz > maxpacked) 
	    multiplier = 2;
	else
	    multiplier = 1;

	timeout.tv_sec = 0;
	timeout.tv_usec = packdelay; /* ms*1000, 0.05ms */

	while(payloadsz < (maxpacked*multiplier) ) {
	    /* try to get next packet */
    	    FD_ZERO(&rfds);
    	    FD_SET(fd, &rfds);
    	    ret = select(fd+1, &rfds, NULL, NULL, &timeout);
	    if (ret<=0) {
		break;
	    }

	    prevavail = read(fd,prevptr,MAXPAYLOAD);
	    /* TODO: unlikely */
	    if (prevavail < 0) {
		perror("Invalid situation\n");
		prevavail = 0;
		continue;
		//break;
	    }

	    if (prevavail + payloadsz <= (maxpacked * multiplier)) {
		/* Still small, merge packets */
		ip[1] |= BIT_PACKED;
		memcpy(payloadptr+payloadsz,prevptr,prevavail);
		payloadsz += prevavail;
		prevavail = 0;
	    } else {
		/* This packet too big, send it alone */
		break;
	    }
	}



#ifdef HAVE_LIBLZO2
	if (compression) {
	    compressedsz = MAXPAYLOAD*2;
	    ret = lzo1x_1_compress(payloadptr,payloadsz,compressed,(lzo_uintp)&compressedsz,wrkmem);

	    /* Adaptive compression */
	    if (compressedsz >= payloadsz || compressedsz > MAXPAYLOAD) {
		compressedsz = 0;
	    } else {
		ip[1] |= BIT_COMPRESSED;
		memcpy(payloadptr,compressed,compressedsz);
		payloadsz = compressedsz;
	    }
	}
#else
	compressedsz = 0;
#endif


//#ifdef GCRYPT
//	gcry_md_hash_buffer(GCRY_MD_CRC32,cksumbuf,ip,payloadsz+2);
//#endif

	pthread_mutex_lock(&raw_mutex);
	if(sendto(raw_socket, ip, payloadsz+2, 0,(struct sockaddr *)&tunnel->daddr, (socklen_t)sizeof(daddr)) < 0)
		perror("send() err");
	pthread_mutex_unlock(&raw_mutex);

    }
    return(NULL);    
}

int main(int argc,char **argv)
{
    struct thr_rx thr_rx_data;
    int ret, i, sn,rc, protocol = 50, c, len;
    Tunnel *tunnel;
    struct sigaction sa;
    struct stat mystat;
    char section[IFNAMSIZ];
    char strbuf[256];
    char *configname = NULL;
    char *bindaddr = NULL;
    char defaultcfgname[] = "/etc/vip.cfg";
    pthread_t *threads;
    pthread_attr_t attr;
    void *status;
    int optval=262144;


  while (1)
         {

	    static struct option long_options[] =
             {
               {"protocol",  required_argument, 0, 'p'},
               {"config",  required_argument, 0, 'c'},
               {"bind",  required_argument, 0, 'b'},
               {"help",  no_argument, 0, 'h'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
	    int option_index = 0;
     
	    c = getopt_long (argc, argv, "c:p:b:h", long_options, &option_index);
          /* Detect the end of the options. */
           if (c == -1)
             break;
     
           switch (c)
             {
             case 'p':
		protocol = atoi(optarg);
               break;

             case 'b':
		len = strlen(optarg) + 1;
		bindaddr = malloc(len);
		strncpy(bindaddr,optarg,len);
               break;

             case 'c':
		len = strlen(optarg) + 1;
		configname = malloc(len);
		strncpy(configname,optarg,len);
               break;
     
             case 'h':
		printf("Available options:\n");
		printf("--protocol 		- Protocol \n");
		printf("--config 		- Config path\n");
		printf("--bind 			- Bind address\n");
		printf("--help			- Help\n");
//		printf("--triggeroutage		- Detect outage, missed packets/packets ok (0/0)\n");
               /* getopt_long already printed an error message. */
		exit(1);
               break;
     
             default:
               abort ();
             }
         }                            

//#ifdef HAVE_LIBLZO2
//    ret = lzo_init();    
//#endif

    printf("Virtual IP %s\n",PACKAGE_VERSION);
    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");

    thr_rx_data.raw_socket = socket(PF_INET, SOCK_RAW, protocol);
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof (optval)))
	perror("setsockopt(RCVBUF)");
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof (optval)))
	perror("setsockopt(SNDBUF)");

    if (bindaddr != NULL) {
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, bindaddr, (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
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

    if (configname == NULL)
	configname = defaultcfgname;

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
	memset(tunnel->daddr.sin_zero, 0x0, sizeof(tunnel->daddr.sin_zero));
	tunnel->id = (int)ini_getl(section,"id",0,configname);
	/* TODO: What is max value of tunnel? */
	if (tunnel->id == 0 || tunnel->id > 255) {
	    warn("ID of \"%d\" is not correct\n", tunnel->id);
	    exit(-1);
	}
	/* Allocate for each thread */
	tunnel->thr_tx_data = malloc(sizeof(struct thr_tx));
        tunnel->thr_tx_data->tunnel = tunnel;
	tunnel->thr_tx_data->cpu = sn+1;
	tunnel->thr_tx_data->packdelay = (int)ini_getl(section,"delay",1000,configname);
	tunnel->thr_tx_data->maxpacked = (int)ini_getl(section,"maxpacked",1500,configname);
	tunnel->thr_tx_data->compression = (int)ini_getl(section,"compression",1,configname);
        tunnel->thr_tx_data->raw_socket = thr_rx_data.raw_socket;
	if (tunnel->thr_tx_data->maxpacked > 1500)
	    tunnel->thr_tx_data->maxpacked = 1500;
	printf("Name %s ID %d Delay %d maxpacked %d compression %d\n",tunnel->name,tunnel->id,tunnel->thr_tx_data->packdelay,tunnel->thr_tx_data->maxpacked,tunnel->thr_tx_data->compression);
	//printf("Max packed %d\n",tunnel->thr_tx_data->maxpacked);
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


//    memset(&sa, 0x0,sizeof(sa));
//    sa.sa_handler = term_handler;
//    sigaction( SIGTERM , &sa, 0);
//    sigaction( SIGINT , &sa, 0);

    threads = malloc(sizeof(pthread_t)*(numtunnels+1));

    /* Fork after creating tunnels, useful for scripts */
    ret = daemon(1,1);


    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    rc = pthread_create(&threads[0], &attr, thr_rx, (void *)&thr_rx_data);

    for(i=0;i<numtunnels;i++)
    {
        tunnel=tunnels + i;
        fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
        rc = pthread_create(&threads[i+1], &attr, thr_tx, (void *)tunnel->thr_tx_data);
    }

    rc = pthread_join(threads[0], &status);

    return(0);
}
