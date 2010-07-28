CFLAGS = -Wall
LIBS = -lnet
TARGET = arpspoof

arpspoof: arpspoof.c
	$(CC) arpspoof.c -o $(TARGET) $(LIBS) $(CFLAGS)
	strip $(TARGET)

clean:
	rm $(TARGET)
