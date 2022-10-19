package main

import (
	"log"
	"net"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

// Listener is the core struct
type Listener struct {
	c   *ipv6.PacketConn
	ifi *net.Interface
}

//type listener interface {
//	io.Closer
//}

// Servers contains state for a running server (with possibly multiple interfaces/listeners)
type Servers struct {
	listeners []Listener
	errors    chan error
}

var bufpool = sync.Pool{New: func() interface{} { r := make([]byte, MaxDatagram); return &r }}

// NewListener creates a new instance of DHCP listener
func NewListener(ifi *net.Interface) (*Listener, error) {
	addr := net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
		Zone: ifi.Name,
	}

	log.Printf("Starting DHCPv6 server for Interface %s", ifi.Name)
	l6 := Listener{}
	//intf, _ := net.InterfaceByName(addr.Zone)
	udpConn, err := server6.NewIPv6UDPConn(addr.Zone, &addr)
	if err != nil {
		ll.Warnf("failed to create a UDP Conn for Ifi %s: %s", ifi.Name, err)
		return nil, err
	}
	l6.c = ipv6.NewPacketConn(udpConn)
	err = l6.c.SetControlMessage(ipv6.FlagInterface, true)
	l6.c.JoinGroup(ifi, &addr)

	return &l6, nil
}

// Listen staifiRoutes listening for incoming DHCP requests
func (l *Listener) Listen6() error {
	ll.Infof("Listen %s", l.c.LocalAddr())
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] //Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.c.ReadFrom(b)
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go l.HandleMsg6(b[:n], oob, peer.(*net.UDPAddr))
	}
}

// Wait waits until the end of the execution of the server.
func (s *Servers) Wait() error {
	ll.Debugf("waiting")
	err := <-s.errors
	s.Close()
	return err
}

// Close closes all listening connections
func (s *Servers) Close() {
	for _, srv := range s.listeners {
		srv.c.Close()
	}
}
