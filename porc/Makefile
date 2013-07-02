

BINS	  =	relay/relay_main.bin 							\
			client/client_main.bin 							\
			socks_sample_client/socks_sample_client.bin 	\
			directory/directory.bin 						\
			set_dir_utility/set_dir_utility.bin
			
CC        = gcc
CFLAGS	= -O0 -Wall $(INCLUDE) `pkg-config gnutls --cflags` `libgcrypt-config --cflags`
LIBS	= `pkg-config gnutls --libs` `libgcrypt-config --libs`
DIRS := ${shell find src/ -type d -print}
SRC       = $(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))
OBJ       = $(patsubst src/%.c,build/%.o,$(SRC))
RBINS 	  =	$(foreach bin,$(BINS),build/$(bin))
	
%client_main.bin: 	build/client/select.o build/lib/tls.o \
					build/lib/socks.o build/lib/tcp.o build/lib/chained_list.o  \
					build/lib/signaling.o build/client/client_main.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ $^ $(LIBS) -lpthread

%directory.bin: build/directory/directory.o build/lib/tls.o build/lib/tcp.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ $^ $(LIBS) -lpthread

%relay_main.bin: 	build/relay/relay_main.o build/lib/tls.o build/lib/tcp.o 	\
					build/lib/chained_list.o build/lib/signaling.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ $^ $(LIBS) -lpthread
	
%socks_sample_client.bin: build/socks_sample_client/socks_sample_client.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ $^ $(LIBS) -lpthread
	
%set_dir_utility.bin: build/set_dir_utility/set_dir_utility.o
	@echo "--------------------------------------------------------------------------------"
	@echo [link]
	$(CC) -o $@ $^ $(LIBS) -lpthread

all: mkdir $(RBINS)
	@echo "$(RBINS)"
	@echo ""
	
checkdirs: 
	@echo $(OBJ)
	
build/%.o: src/%.c 
	@echo "--------------------------------------------------------------------------------"
	@echo [CC] $<
	$(CC) -c $(CFLAGS) $< -o $@ 

mkdir: 
	mkdir -p $(patsubst src/%,build/%,$(DIRS))
	
clean:
	rm -f $(RBINS)

