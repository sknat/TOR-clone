CC	= gcc
CFLAGS	= -O0 -Wall $(INCLUDE) `pkg-config gnutls --cflags`
LIBS	= `pkg-config gnutls --libs`

SRC	=	relay.c client.c sclient.c mytls.c socks.c mytcp.c directory.c setdir.c
OBJ	=	relay.o client.o sclient.o mytls.o socks.o mytcp.o directory.o setdir.o
BINS	=	relay.exe client.exe sclient.exe directory.exe setdir.exe

all:	$(BINS)
	@echo "    $(BINS)"
	@echo ""

setdir.exe:	setdir.o
	@echo [link]
	$(CC) -o $@ setdir.o $(LIBS)

relay.exe:	relay.o mytls.o mytcp.o
	@echo [link]
	$(CC) -o $@ relay.o mytls.o mytcp.o $(LIBS) -lpthread

directory.exe:	directory.o mytls.o mytcp.o
	@echo [link]
	$(CC) -o $@ directory.o mytls.o mytcp.o $(LIBS) -lpthread

client.exe:	client.o mytls.o socks.o mytcp.o
	@echo [link]
	$(CC) -o $@ client.o mytls.o socks.o mytcp.o $(LIBS) -lpthread

sclient.exe:	sclient.o
	@echo [link]
	$(CC) -o $@ sclient.o $(LIBS)

socks.exe:	socks.o mytcp.o
	@echo [link]
	$(CC) -o $@ mytcp.o socks.o $(LIBS)

.c.o:
	@echo [CC] $<
	@$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJ) *~ $(BINS)
