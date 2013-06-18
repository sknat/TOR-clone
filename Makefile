all:
	g++ tsocks.cpp -o tsocks.o -lpthread

clean: 
	rm -f *.o
