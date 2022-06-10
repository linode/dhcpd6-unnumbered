package main

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

// Listener is the core struct
type Listener struct {
	c   *ipv6.PacketConn
	ifi *net.Interface
	sIP net.IP
}

type listener interface {
	io.Closer
}

// Servers contains state for a running server (with possibly multiple interfaces/listeners)
type Servers struct {
	listeners []Listener
	errors    chan error
}

var bufpool = sync.Pool{New: func() interface{} { r := make([]byte, MaxDatagram); return &r }}

// NewListener creates a new instance of DHCP listener
func StartListeners6() (*Servers, error) {
	srv := Servers{
		errors: make(chan error),
	}
	addrs, err := allIntfsLLMulticast()
	if err != nil {
		ll.Warnf("failed to join multicast groups: %s", err)
	}
	log.Println("Starting DHCPv6 server")
	for _, addr := range addrs {
		l6 := Listener{}
		intf, _ := net.InterfaceByName(addr.Zone)
		udpConn, err := server6.NewIPv6UDPConn(addr.Zone, &addr)
		if err != nil {
			ll.Warnf("failed to create a UDP Conn: %s", err)
			goto cleanup
		}
		l6.c = ipv6.NewPacketConn(udpConn)
		err = l6.c.SetControlMessage(ipv6.FlagInterface, true)
		l6.c.JoinGroup(intf, &addr)
		srv.listeners = append(srv.listeners, l6)
		go func() {
			srv.errors <- l6.Listen6()
		}()
	}
	return &srv, nil

cleanup:
	srv.Close()
	return nil, err
}

// SetSource sets the DHCP server IP and Identified in the offer
func (l *Listener) SetSource(ip net.IP) {
	l.sIP = ip
	ll.Infof("Sending from %s", l.sIP)
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
