CFLAGS = -Wall -O2
DBFLAGS = -g
LIBS = -lnet -lpcap

all: arpspoof synflood

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
