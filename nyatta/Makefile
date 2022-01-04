CC=gcc -Wall
CLIB=-lpcap -lsodium -pthread -lcurl

nyatta:
	$(CC) -o nyatta src/logger.c src/utils.c src/crypto.c src/message.c src/network.c src/nyatta.c $(CLIB)

clean:
	rm nyatta