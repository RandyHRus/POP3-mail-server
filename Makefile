CC=gcc
#
# If you want to enable the "standard" server behaviour of forking a process
# to handle each incoming socket connection, then define the symbol DOFORK
# using the following line. 
# CFLAGS=-g -Wall -std=gnu11 -DDOFORK
CFLAGS=-g -Wall -std=gnu11

all: mypopd 

test:	mypopd
	./test.sh

mypopd: mypopd.o netbuffer.o mailuser.o server.o util.o
	gcc $(CFLAGS) -o mypopd mypopd.o netbuffer.o mailuser.o server.o util.o 

mypopd.o: mypopd.c netbuffer.h mailuser.h server.h util.h
netbuffer.o: netbuffer.c netbuffer.h util.h
mailuser.o: mailuser.c mailuser.h util.h
server.o: server.c server.h util.h
util.o: util.h

clean:
	-rm -rf mypopd mypopd.o netbuffer.o mailuser.o server.o util.o mailtmp* mail.store

tidy: clean
	-rm -rf *~ out.p.?
