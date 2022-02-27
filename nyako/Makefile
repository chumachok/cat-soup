TARGET=-target bpf
CC=clang -g -O2 -Wall

nyako_kern:
	$(CC) $(TARGET) -c src/nyako_kern.c -o nyako_kern.o

nyako:
	$(CC) -o nyako.o src/logger.c src/bpf_helpers.c src/nyako.c -lbpf

load:
	xdp-loader load -vv -m skb -s nyako_kern eth1 nyako_kern.o

unload:
	xdp-loader unload -a eth1

clean:
	rm nyako.o