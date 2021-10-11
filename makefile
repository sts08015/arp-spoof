CC = g++
LDLIBS=-lpcap -lpthread

all: arp-spoof

remake: clean arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
