sym:
	gcc -o sym_cypher.o sym_cypher.c `libgcrypt-config --cflags --libs`

asym:
	gcc -o asym_cypher.o asym_cypher.c `libgcrypt-config --cflags --libs`
	 
clean:
	rm -f *.o*

test: 
	gcc -o testlibrary.o testlibrary.c `libgcrypt-config --cflags --libs`
