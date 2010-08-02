/**
 * utils.h
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

#ifndef SYNCLOTIUS_UTILS
#define SYNCLOTIUS_UTILS

#include <stdio.h>

#include <libnet.h>
#include <pcap.h>

#define L_IS_TYPE(level, type) ((level & type) == type)
#define L_INFO    0x01
#define L_MSG     0x02
#define L_FATAL   0x04
#define L_LIBNET  0x08
#define L_PCAP    0x10

#ifndef IP_ADDR_LEN
# define IP_ADDR_LEN 4
#endif

void slog_init(const char* g_prg_name, int g_verb_mode);
void slog(int level, void* ptr, const char *fmt, ...);

#endif /* SYNCLOTIUS_UTILS */
