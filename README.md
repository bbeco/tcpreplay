#Tcpreplay clone
##Overview
This software is a cloned version of the original one, made for working with
netmap (see http://info.iet.unipi.it/~luigi/netmap/ for more information 
about netmap). 
This software works in two different modes:
* Replay
* Pcap
Replay
In replay mode the user provides two different netmap interfaces.
The software accepts all the incoming packets from one interface and retransmits 
them on the other one. This retransmission works in both direction.
Pcap
In this mode the user provides one interface and one capture file (.cap).
The software replays the content of the file to the specified interface. In
particular the software supports three different transmission timing: real, 
fixed bandwidth and maximum speed.

##Usage options
Replay mode accepts the following options:
* B	bandwidth in bps
* D	delay in seconds
* Q	qsize in bytes
* L	loss probability
* i	interface name (two mandatory)
* v	verbose
* b	batch size

If the B option is used, tcpreplay transmits packets with the given speed.

Specifiyng the delay options let the program randomly choose a sequence of 
values to be used as delays introduced at each packet.
Arguments for the delay options are specified in a comma separated manner. The 
first argument is the distribution the delays are extracted from; it must be a 
string like const (constant delays), uniform (uniform distribution) and exp 
(exponential distribution). The second argument is the value to be used as delay
when the user has specified const as the first argument.

The Q options set the queue size to the given value. If the user does not 
specify a queue size, 50k is used as default value.

The L option sets a loss probability. Loss is expressed as packet or bit error 
rate, which is an absolute number between 0 and 1 (typically small).
Currently implemented options

    plr,p		uniform packet loss rate p, independent
				of packet size

    burst,p,lmin,lmax 	burst loss with burst probability p and
						burst length uniformly distributed between
						lmin and lmax

    ber,p		uniformly distributed bit error rate p,
				so actual loss prob. depends on size.

The I option specifies the interface to be used. Two interfaces are mandatory 
while operating in replay mode. On the other hand, in pcap mode, tcpreplay needs
just a single interface.

The options that require numerical arguments can handle multiplication suffixes.
Tcpreplay support time suffixes: n for nanosecond, u for microseconds, m for 
milliseconds and s for seconds. If no suffix has been provided, seconds is 
automatically selected.

For data size, like the one needed after the Q option, the user can specify k or
K for kilobyte (1024 bytes), m or M for Megabyte (1024^2 bytes) or g or G for 
gigabyte (1024^3 bytes). If no suffix has been provided, byte is automatically
selected.

For speed, like the arguments needed after the B option, the user can specify k 
or K for kilobit/s (1000 bit/s), m or M for megabit/s (1000^2 bit/s) or g or G 
for gigabit (1000^3 bit/s). If no suffix has been provided, bit per seconds is 
automatically selected.

* m	pcap transmission mode (real/fast/fixed)
