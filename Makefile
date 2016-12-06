CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic

pevent:*.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm pevent
