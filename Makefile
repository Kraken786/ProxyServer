CC = gcc
CFLAGS = -Wall -Wextra -pthread -g -DDEBUG
LDFLAGS = -lssl -lcrypto
DEPS = proxy_server.h linkedlist.h queue.h logging.h
OBJ = proxy_server.o linkedlist.o queue.o logging.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

proxy_server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o proxy_server *.log
