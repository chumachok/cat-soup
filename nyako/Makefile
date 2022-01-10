CC=clang -g -O2 -Wall -target bpf

nyako_kern:
	$(CC) -c src/nyako_kern.c -o nyako_kern.o

load:
	xdp-loader load -vv -m skb -s nyako_kern eth1 nyako_kern.o

unload:
	xdp-loader unload -a eth1

clean:
	rm nyako_kern.o