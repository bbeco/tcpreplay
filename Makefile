CFLAGS= -O2 -Wall -Werror
LDLIBS += -lpthread
LDLIBS += -lm # use log2 for stats

prodcons: rpcap.o prodcons.o
rpcap.o prodcons.o: rpcap.h

clean:
	rm prodcons *.o
