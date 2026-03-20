CC = gcc
OPENSSL_DIR = /opt/openssl-3.5
CFLAGS = -Wall -Wextra -O2 -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib64 -Wl,-rpath=$(OPENSSL_DIR)/lib64
LIBS = -lssl -lcrypto

all: hybrid_server hybrid_client

hybrid_server: hybrid_tls_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

hybrid_client: hybrid_tls_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean:
	rm -f hybrid_server hybrid_client *.o

run-server:
	./hybrid_server

run-client:
	./hybrid_client

test: all
	@echo "Starting server..."
	@./hybrid_server > /dev/null 2>&1 & echo $$! > server.pid
	@sleep 2
	@echo "Running client..."
	@./hybrid_client
	@kill `cat server.pid` 2>/dev/null || true
	@rm -f server.pid

.PHONY: all clean run-server run-client test
