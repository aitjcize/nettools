CFLAGS = -Wall -O2
DBFLAGS = -g
LIBS = -lnet -lpcap
TARGETS = arpspoof synflood

all: $(TARGETS)

arpspoof: arpspoof.o utils.o arp_utils.o
	$(CC) arpspoof.o utils.o arp_utils.o -o arpspoof $(LIBS) $(CFLAGS)
	strip arpspoof

synflood: synflood.o utils.o arp_utils.o
	$(CC) synflood.o utils.o arp_utils.o -o synflood $(LIBS) $(CFLAGS)
	strip synflood

arpspoof.o: arpspoof.c
	$(CC) -c arpspoof.c $(CFLAGS)

synflood.o: synflood.c
	$(CC) -c synflood.c $(CFLAGS)

utils.o: utils.c
	$(CC) -c utils.c $(CFLAGS)

arp_utils.o: arp_utils.c
	$(CC) -c arp_utils.c $(CFLAGS)

install:
	cp $(TARGETS) /usr/sbin

clean:
	rm arpspoof synflood arpspoof.o synflood.o utils.o arp_utils.o
