package main

import (
	"fmt"
	"net"
	"regexp"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

var bufpool = sync.Pool{New: func() interface{} { r := make([]byte, MaxDatagram); return &r }}

// Listener is the core struct
type Listener struct {
	c     *ipv6.PacketConn
	ifi   *net.Interface
	Flags *ListenerOptions
}

type ListenerOptions struct {
	prefix *net.IPNet
	regex  *regexp.Regexp
}

func (lo *ListenerOptions) SetPrefix(p *net.IPNet) {
	ll.Infof("Advertising IPs out of the %s Prefix", p.String())
	lo.prefix = p
}

// NewListener creates a new instance of DHCP listener
func NewListener(idx int, o *ListenerOptions) (*Listener, error) {
	ifi, err := net.InterfaceByIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("unable to get interface: %v", err)
	}

	addr := net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
		Zone: ifi.Name,
	}

	ll.Infof("Starting DHCPv6 server for Interface %s", ifi.Name)
	udpConn, err := server6.NewIPv6UDPConn(addr.Zone, &addr)
	if err != nil {
		//ll.Warnf("failed to create a UDP Conn for Ifi %s: %s", ifi.Name, err)
		return nil, err
	}
	c := ipv6.NewPacketConn(udpConn)
	if err := c.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		return nil, err
	}
	c.JoinGroup(ifi, &addr)

	return &Listener{
		c:     c,
		ifi:   ifi,
		Flags: o,
	}, nil
}

func (l *Listener) Close() error {
	return l.c.Close()
}

// Listen staifiRoutes listening for incoming DHCP requests
func (l *Listener) Listen() error {
	ll.Debugf("Listen %s", l.ifi.Name)
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] //Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.c.ReadFrom(b)
		if err != nil {
			//ll.Warnf("Error reading from connection: %v", err)
			return checkNetOpError(err)
		}

		go l.HandleMsg6(b[:n], oob, peer.(*net.UDPAddr))
	}
}
