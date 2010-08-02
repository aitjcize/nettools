/**
 * arp_utils.h
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

#ifndef SYNCLOTIUS_ARP_UTILS
#define SYNCLOTIUS_ARP_UTILS

#include <libnet.h>
#include <pcap.h>

typedef struct _ip_mac_pair {
  int complete;                  /* whether ip and mac are both specified */
  const char* intf;
  in_addr_t* ip;
  struct libnet_ether_addr* mac;
} ip_mac_pair;

int get_mac_by_ip(char* intf_arp, in_addr_t ip, struct libnet_ether_addr *mac);
void arp_packet_handler_cb(u_char* imp, const struct pcap_pkthdr* pkinfo,
                           const u_char* packet);
void build_arp(libnet_t* l, int op, u_int8_t* src_ip, u_int8_t* src_mac,
               u_int8_t* dst_ip, u_int8_t* dst_mac);

#endif /* SYNCLOTIUS_ARP_UTILS */
