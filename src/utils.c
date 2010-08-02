/**
 * utils.c
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

static const char* g_prg_name = 0;
static int g_verb_mode = 0;

void slog_init(const char* prg_name, int verb_mode) {
  g_prg_name = prg_name;
  g_verb_mode = verb_mode;
}

void slog(int level, void* ptr, const char *fmt, ...) {
  va_list vap;

  if (L_IS_TYPE(level, L_INFO) && !g_verb_mode)
    return;

  if (L_IS_TYPE(level, L_LIBNET)) {
    char* tmp = libnet_geterror((libnet_t*)ptr);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", g_prg_name, tmp);
  }

  if (L_IS_TYPE(level, L_PCAP)) {
    char* tmp = pcap_geterr((pcap_t*)ptr);
    if (tmp && strlen(tmp) != 0)
      fprintf(stderr, "%s: %s\n", g_prg_name, tmp);
  }

  if (L_IS_TYPE(level, L_MSG)) {
    va_start(vap, fmt);
    vfprintf(stdout, fmt, vap);
    va_end(vap);
  } else {
    fprintf(stderr, "%s: ", g_prg_name);
    va_start(vap, fmt);
    vfprintf(stderr, fmt, vap);
    va_end(vap);
  }

  if (!L_IS_TYPE(level, L_INFO) && !L_IS_TYPE(level, L_MSG))
    exit(1);
}
