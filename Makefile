CFLAGS= -O2 -Wall -Werror
LDFLAGS += -lpthread
LDFLAGS += -lm # use log2 for stats

prodcons: rpcap.o prodcons.o
rpcap.o prodcons.o: rpcap.h

clean:
	rm prodcons *.o
