CC = gcc
CFLAGS = -g -Wall

default:
	$(CC) pevent.c -o pevent $(CFLAGS)

clean:
	rm pevent
