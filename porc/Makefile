CC	= gcc
CFLAGS	= -O0 -Wall $(INCLUDE) `pkg-config gnutls --cflags` `libgcrypt-config --cflags`
LIBS	= `pkg-config gnutls --libs` `libgcrypt-config --libs`

SRC	=	crypto.c signaling.c porc.c relay.c relaymain.c clientmain.c select.c sclient.c mytls.c socks.c mytcp.c directory.c setdir.c chainedlist.c
OBJ	=	crypto.o signaling.o porc.o relay.o relaymain.o clientmain.o select.o sclient.o mytls.o socks.o mytcp.o directory.o setdir.o chainedlist.o
BINS	=	relay.exe client.exe sclient.exe directory.exe setdir.exe

all:	$(BINS)
	@echo "    $(BINS)"
	@echo ""

setdir.exe:	setdir.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ setdir.o $(LIBS)

relay.exe:	relaymain.o mytls.o mytcp.o chainedlist.o signaling.o crypto.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ relaymain.o mytls.o mytcp.o chainedlist.o signaling.o crypto.o $(LIBS) -lpthread

directory.exe:	directory.o mytls.o mytcp.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ directory.o mytls.o mytcp.o $(LIBS) -lpthread

client.exe:	clientmain.o select.o mytls.o socks.o mytcp.o chainedlist.o porc.o signaling.o crypto.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ clientmain.o select.o mytls.o socks.o mytcp.o chainedlist.o $(LIBS) porc.o signaling.o crypto.o -lpthread

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
	rm -f ./*.stackdump
	rm -f ./*/*.stackdump
