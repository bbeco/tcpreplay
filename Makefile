CFLAGS= -O2 -Wall -Werror
LDFLAGS += -lpthread
LDFLAGS += -lm # use log2 for stats

prodcons: rpcap.o prodcons.o

clean:
	rm prodcons *.o
