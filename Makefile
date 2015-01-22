all: gatorcrypt gatordec

gatorcrypt : gatorcrypt.o
	gcc -o gatorcrypt gatorcrypt.o `libgcrypt-config --libs` #for linking the program with the library
gatorcrypt1.o : gatorcrypt.c
	gcc -c gatorcrypt.c `libgcrypt-config --cflags` #to ensure that the compiler can find the Libgcrypt header file
gatordec : gatordec.o
	gcc -o gatordec gatordec.o `libgcrypt-config --libs`
gatordec.o : gatordec.c
	gcc -c gatordec.c `libgcrypt-config --cflags`
clean:
	rm  gatorcrypt.o gatorcrypt gatordec.o gatordec
