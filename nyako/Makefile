CC=clang -O2 -Wall -target bpf

packet_processor:
	$(CC) -c src/packet_processor.c -o packet_processor.o

load:
	xdp-loader load -m skb -s packet_processor eth1 packet_processor.o

unload:
	xdp-loader unload -a eth1

clean:
	rm nyako