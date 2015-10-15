CFLAGS=-g -Wall

all: instantcloud

instantcloud: instantcloud.c cloud.o cloud.h
	gcc $(CFLAGS) instantcloud.c -o instantcloud  cloud.o -lcurl

cloud.o: cloud.c cloud.h
	gcc $(CFLAGS) -c cloud.c


clean:
	-rm instantcloud *.o
