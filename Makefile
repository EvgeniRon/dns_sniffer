CC=gcc
CFLAGS=-I. -g
DEPS = socket.h
OBJ = dns_sniffer.o socket.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

dns_sniffer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf *.o