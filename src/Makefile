CFLAGS = -Wall -O2
DBFLAGS = -g
LIBS = -lnet -lpcap
TARGETS = arpspoof synflood

all: $(TARGETS)

install:
	mv $(TARGETS) /usr/sbin

arpspoof: arpspoof.c
	$(CC) arpspoof.c -o arpspoof $(LIBS) $(CFLAGS)
	strip arpspoof

arpspoof_debug:
	$(CC) arpspoof.c -o arpspoof $(LIBS) $(CFLAGS) $(DBFLAGS)

synflood: synflood.c
	$(CC) synflood.c -o synflood $(LIBS) $(CFLAGS)
	strip synflood

synflood_debug:
	$(CC) synflood.c -o synflood $(LIBS) $(CFLAGS) $(DBFLAGS)

clean:
	rm arpspoof synflood 
