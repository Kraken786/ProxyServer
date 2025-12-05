CC = gcc
CFLAGS = -Wall -Wextra -pthread -g -DDEBUG
LDFLAGS = -lssl -lcrypto -lnghttp2
DEPS = proxy_server.h linkedlist.h queue.h logging.h stats.h control.h config.h http2_handler.h tls_parser.h
OBJ = proxy_server.o linkedlist.o queue.o logging.o stats.o control.o config.o http2_handler.o tls_parser.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

proxy_server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o proxy_server *.log
