CFLAGS=	 -Wall -g
LDFLAGS= -g
LDLIBS = -lpcap

all: acl-dhcp

clean:
	-rm acl-dhcp

acl-dhcp: acl-dhcp.c
