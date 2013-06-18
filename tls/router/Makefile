server:
	gcc -o server.o server.c `pkg-config gnutls --cflags --libs`

client:
	gcc -o client.o client.c `pkg-config gnutls --cflags --libs`

clean:
	rm -f *.o
