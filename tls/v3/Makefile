all: relay client tsocks sclient

relay:
	gcc -o relay.o relay.c mytls.c `pkg-config gnutls --cflags --libs` -lpthread

client:
	gcc -o client.o client.c mytls.c `pkg-config gnutls --cflags --libs`

sclient:
	gcc -o sclient.o sclient.c

tsocks:
	gcc tsocks.c -o tsocks.o -lpthread

clean:
	rm -f *.o *~
