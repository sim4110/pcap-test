LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c

clean:
	rm -rf pcap-test *.o