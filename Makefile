LDFLAGS=-lpthread -lmnl -lnetfilter_queue

all: localbreakout

localbreakout: localbreakout.o
	$(CC) -o localbreakout localbreakout.o $(LDFLAGS)

localbreakout.o: localbreakout.c
	$(CC) $(CFLAGS) -c localbreakout.c

clean:
	rm -rf localbreakout *.o
