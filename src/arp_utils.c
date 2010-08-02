/**
 * arp_utils.c
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

#include "utils.h"
#include "arp_utils.h"

int get_mac_by_ip(char* intf_arp, in_addr_t ip, struct libnet_ether_addr *mac) {

  int i = 0;
  ip_mac_pair imp = {0, intf_arp, &ip, mac};
  char err_buf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE?
               LIBNET_ERRBUF_SIZE: PCAP_ERRBUF_SIZE];

  libnet_t* l_arp = 0;
  pcap_t* p_arp = 0;
  struct bpf_program bp;

  /* libnet init */
  if (!(l_arp = libnet_init(LIBNET_LINK_ADV, intf_arp, err_buf)))
    slog(L_FATAL, 0, "libnet_init(): %s\n", libnet_geterror(l_arp));
  else
    slog(L_INFO, 0, "libnet_init()\n");

  /* pcap init */
  if (!(p_arp = pcap_open_live(intf_arp, 100, 0, 10, err_buf)))
    slog(L_PCAP, p_arp, "pcap_open_live() error\n");
  else
    slog(L_INFO, 0, "pcap_open_live()\n");

  /* set capture filter */
  if (-1 == pcap_compile(p_arp, &bp, "arp", 0, -1))
    slog(L_PCAP, p_arp, "pcap_compile(): error\n");

  if (-1 == pcap_setfilter(p_arp, &bp))
    slog(L_PCAP, p_arp, "pcap_setfilter(): error\n");

  /* start resolving */
  slog(L_INFO, 0, "resolving MAC address for %s\n",
       libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
  in_addr_t local_ip = libnet_get_ipaddr4(l_arp);
  struct libnet_ether_addr* local_mac = libnet_get_hwaddr(l_arp);

  if (local_mac == NULL)
    slog(L_LIBNET, l_arp, "can't resolve MAC address for localhost\n");

  build_arp(l_arp, ARPOP_REQUEST, (u_int8_t*)&local_ip, (u_int8_t*)local_mac,
               (u_int8_t*)&ip, (u_int8_t*)"\x00\x00\x00\x00\x00\x00");

  slog(L_MSG, 0, "%s: 42 bytes, broadcasting: Who has %s? Tell %s\n", intf_arp,
       libnet_addr2name4(ip, LIBNET_DONT_RESOLVE),
       libnet_addr2name4(local_ip, LIBNET_DONT_RESOLVE));

  do {
    /* send arp request */
    if (-1 == libnet_write(l_arp))
      slog(L_LIBNET, l_arp, "can't send packet\n");

    /* capture arp reply */
    *mac->ether_addr_octet = 0;
    pcap_dispatch(p_arp, 1, arp_packet_handler_cb, (u_char*) &imp);
    if (imp.complete) {
      libnet_clear_packet(l_arp);
      return 1;
    }
    usleep(100000);
  } while (++i < 30); /* try for 3 seconds */

  libnet_destroy(l_arp);
  pcap_close(p_arp);
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
      slog(L_MSG, 0, "%s: %d bytes, received: %s is at ",
           ((ip_mac_pair*)imp)->intf, pkinfo->len,
           libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));

      for (c = 0; c < 6; c++)
        slog(L_MSG, 0, "%.2x%c", ((u_char*)((ip_mac_pair*)imp)->mac)[c],
               (c < 5)? ':': '\n');
      return;
    }
  }
}

void build_arp(libnet_t* l, int op, u_int8_t* src_ip, u_int8_t* src_mac,
    u_int8_t* dst_ip, u_int8_t* dst_mac) {

  libnet_ptag_t p_tag;

  if (-1 == (p_tag = libnet_build_arp(      /* construct arp packet */
      ARPHRD_ETHER,                         /* hardware type ethernet */
      ETHERTYPE_IP,                         /* protocol type */
      ETHER_ADDR_LEN,                       /* mac length */
      IP_ADDR_LEN,                          /* protocol length */
      op,                                   /* op type */
      src_mac,                              /* source mac addr */
      src_ip,                               /* source ip addr */
      dst_mac,                              /* dest mac addr */
      dst_ip,                               /* dest ip addr */
      NULL,                                 /* payload */
      0,                                    /* payload length */
      l,                                    /* libnet context */
      0                                     /* 0 stands to build a new one */
  ))) slog(L_LIBNET, l, "can't build arp header\n");

  if (op == ARPOP_REQUEST)
    dst_mac = (u_int8_t*)"\xff\xff\xff\xff\xff\xff";

  if (-1 == (p_tag = libnet_build_ethernet( /* create ethernet header */
      dst_mac,                              /* dest mac addr */
      src_mac,                              /* source mac addr */
      ETHERTYPE_ARP,                        /* protocol type */
      NULL,                                 /* payload */
      0,                                    /* payload length */
      l,                                    /* libnet context */
      0                                     /* 0 to build a new one */
  ))) slog(L_LIBNET, l, "can't build ethernet header\n");
}
