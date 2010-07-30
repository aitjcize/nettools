CFLAGS = -Wall -O2
DBFLAGS = -g
LIBS = -lnet -lpcap
TARGET = arpspoof

arpspoof: arpspoof.c
	$(CC) arpspoof.c -o $(TARGET) $(LIBS) $(CFLAGS)
	strip $(TARGET)

debug:
	$(CC) arpspoof.c -o $(TARGET) $(LIBS) $(CFLAGS) $(DBFLAGS)

clean:
	rm $(TARGET)
