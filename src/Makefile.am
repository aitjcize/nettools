bin_PROGRAMS = arpspoof synflood

arpspoof_CFLAGS = -Wall -O2 -g
arpspoof_LDADD  = -lnet -lpcap
arpspoof_SOURCES = arpspoof.c \
		   arp_utils.c \
		   utils.c

synflood_CFLAGS = -Wall -O2 -g
synflood_LDADD  = -lnet -lpcap
synflood_SOURCES = synflood.c \
		   arp_utils.c \
		   utils.c
