package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"syscall"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

const (
	etherHeaderLen = 14
	ipv6HeaderLen  = 40
	udpHeaderLen   = 8
	etherTypeIPv6  = 0x86DD
)

// Listener is the core struct
type Listener struct {
	c       *ipv6.PacketConn // send-only: used to write DHCPv6 replies
	rawFile *os.File         // AF_PACKET raw socket: receives Ethernet frames so we see the source MAC directly
	ifi     *net.Interface
	Flags   *ListenerOptions
}

type ListenerOptions struct {
	prefix *net.IPNet
	regex  *regexp.Regexp
}

func (lo *ListenerOptions) SetPrefix(p *net.IPNet) {
	ll.Infof("Advertising IPs out of the %s Prefix", p.String())
	lo.prefix = p
}

// NewListener creates a new instance of DHCP listener.
// It opens two sockets on the interface:
//   - a UDP socket joined to the DHCPv6 all-servers multicast group, used only
//     for sending replies (multicast group membership is required so the kernel
//     passes the incoming multicast frames to the network stack);
//   - an AF_PACKET raw socket used for receiving, so that every Ethernet frame
//     is available in full and the source MAC can be read directly from the
//     frame header without relying on the kernel neighbor cache.
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
		return nil, err
	}
	c := ipv6.NewPacketConn(udpConn)
	if err := c.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		_ = c.Close()
		return nil, err
	}
	// Join the multicast group so the kernel (and NIC hardware filter) accepts
	// incoming DHCPv6 multicast frames on this interface.
	if err := c.JoinGroup(ifi, &addr); err != nil {
		_ = c.Close()
		return nil, err
	}

	// Open an AF_PACKET raw socket so we receive the full Ethernet frame and
	// can extract the source MAC without consulting the neighbor cache.
	rawFd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC,
		int(htons(syscall.ETH_P_IPV6)),
	)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to create raw packet socket: %w", err)
	}
	if err := syscall.Bind(rawFd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IPV6),
		Ifindex:  idx,
	}); err != nil {
		_ = syscall.Close(rawFd)
		_ = c.Close()
		return nil, fmt.Errorf("failed to bind raw packet socket: %w", err)
	}

	return &Listener{
		c:       c,
		rawFile: os.NewFile(uintptr(rawFd), ifi.Name),
		ifi:     ifi,
		Flags:   o,
	}, nil
}

func (l *Listener) Close() error {
	// Close the raw socket first so Listen() unblocks, then close the send conn.
	_ = l.rawFile.Close()
	return l.c.Close()
}

// Listen reads incoming Ethernet frames from the AF_PACKET socket, parses each
// DHCPv6 datagram, and dispatches it to HandleMsg6 together with the source MAC
// address read directly from the Ethernet header.
func (l *Listener) Listen() error {
	ll.Debugf("Listen %s", l.ifi.Name)
	buf := make([]byte, MaxDatagram)
	for {
		n, err := l.rawFile.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}

		srcMAC, dhcpPayload, peer, err := parseEthernetFrame(buf[:n])
		if err != nil {
			ll.Debugf("Listen %s: skipping frame: %v", l.ifi.Name, err)
			continue
		}

		// Link-local addresses require the interface zone for the reply.
		peer.Zone = l.ifi.Name

		oob := &ipv6.ControlMessage{IfIndex: l.ifi.Index}

		// Copy the payload out of the shared buffer before handing it to the goroutine.
		pkt := make([]byte, len(dhcpPayload))
		copy(pkt, dhcpPayload)

		go l.HandleMsg6(pkt, oob, peer, srcMAC)
	}
}

// parseEthernetFrame validates and parses an Ethernet frame containing an IPv6
// UDP DHCPv6 datagram destined for the DHCPv6 all-servers multicast address.
// It returns the Ethernet source MAC, the DHCPv6 payload slice (sub-slice of
// frame), and the UDP source address.
func parseEthernetFrame(frame []byte) (srcMAC net.HardwareAddr, dhcpPayload []byte, peer *net.UDPAddr, err error) {
	if len(frame) < etherHeaderLen {
		return nil, nil, nil, fmt.Errorf("frame too short (%d bytes)", len(frame))
	}

	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv6 {
		return nil, nil, nil, fmt.Errorf("not IPv6 (ethertype 0x%04x)", binary.BigEndian.Uint16(frame[12:14]))
	}

	mac := make(net.HardwareAddr, 6)
	copy(mac, frame[6:12])

	ipv6Frame := frame[etherHeaderLen:]
	if len(ipv6Frame) < ipv6HeaderLen {
		return nil, nil, nil, fmt.Errorf("IPv6 header truncated")
	}

	if ipv6Frame[6] != 17 { // next header: UDP
		return nil, nil, nil, fmt.Errorf("not UDP (next header %d)", ipv6Frame[6])
	}

	if !net.IP(ipv6Frame[24:40]).Equal(dhcpv6.AllDHCPRelayAgentsAndServers) {
		return nil, nil, nil, fmt.Errorf("not DHCPv6 multicast dst")
	}

	srcIP := make(net.IP, 16)
	copy(srcIP, ipv6Frame[8:24])

	udpFrame := ipv6Frame[ipv6HeaderLen:]
	if len(udpFrame) < udpHeaderLen {
		return nil, nil, nil, fmt.Errorf("UDP header truncated")
	}

	if binary.BigEndian.Uint16(udpFrame[2:4]) != uint16(dhcpv6.DefaultServerPort) {
		return nil, nil, nil, fmt.Errorf("not DHCPv6 server port (%d)", binary.BigEndian.Uint16(udpFrame[2:4]))
	}

	dhcp := udpFrame[udpHeaderLen:]
	if len(dhcp) == 0 {
		return nil, nil, nil, fmt.Errorf("empty DHCPv6 payload")
	}

	return mac, dhcp, &net.UDPAddr{
		IP:   srcIP,
		Port: int(binary.BigEndian.Uint16(udpFrame[0:2])),
	}, nil
}
