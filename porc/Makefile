CC	= gcc
CFLAGS	= -O0 -Wall $(INCLUDE) `pkg-config gnutls --cflags`
LIBS	= `pkg-config gnutls --libs`

SRC	=	relay.c clientmain.c select.c sclient.c mytls.c socks.c mytcp.c directory.c setdir.c relaychainedlist.c clientchainedlist.c
OBJ	=	relay.o clientmain.o select.o sclient.o mytls.o socks.o mytcp.o directory.o setdir.o relaychainedlist.o clientchainedlist.o
BINS	=	relay.exe client.exe sclient.exe directory.exe setdir.exe

all:	$(BINS)
	@echo "    $(BINS)"
	@echo ""

setdir.exe:	setdir.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ setdir.o $(LIBS)

relay.exe:	relay.o mytls.o mytcp.o relaychainedlist.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ relay.o mytls.o mytcp.o relaychainedlist.o $(LIBS) -lpthread

directory.exe:	directory.o mytls.o mytcp.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ directory.o mytls.o mytcp.o $(LIBS) -lpthread

client.exe:	clientmain.o select.o mytls.o socks.o mytcp.o clientchainedlist.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ clientmain.o select.o mytls.o socks.o mytcp.o clientchainedlist.o $(LIBS) -lpthread

sclient.exe:	sclient.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ sclient.o $(LIBS)

.c.o:
	@echo "--------------------------------------------------------------------------------"
	@echo [CC] $<
	@$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJ) *~ $(BINS)
