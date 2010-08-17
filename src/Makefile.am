bin_PROGRAMS = arpspoof synflood

LDADD  = -lnet -lpcap
AM_CFLAGS = -Wall -O2 -g

arpspoof_SOURCES = arpspoof.c \
		   arp_utils.h \
		   arp_utils.c \
		   utils.h \
		   utils.c

synflood_SOURCES = synflood.c \
		   arp_utils.h \
		   arp_utils.c \
		   utils.h \
		   utils.c
