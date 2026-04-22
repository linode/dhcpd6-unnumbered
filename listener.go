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
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
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

	// Bind the send socket to [::]:547 on the interface — NOT to the multicast
	// group address.  If bound to ff02::1:2, Linux refuses to use a multicast
	// address as the source of a unicast reply (EADDRNOTAVAIL).  We join the
	// multicast group separately below so the kernel still delivers incoming
	// multicast solicits to the network stack (needed for multicast group
	// membership and NIC hardware filter).
	mcastAddr := net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
		Zone: ifi.Name,
	}
	bindAddr := net.UDPAddr{
		IP:   net.IPv6zero,
		Port: dhcpv6.DefaultServerPort,
		Zone: ifi.Name,
	}

	ll.Infof("Starting DHCPv6 server for Interface %s", ifi.Name)
	udpConn, err := server6.NewIPv6UDPConn(ifi.Name, &bindAddr)
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
	if err := c.JoinGroup(ifi, &mcastAddr); err != nil {
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
	// Attach a BPF filter so the kernel discards all non-DHCPv6 frames before
	// copying them to userspace: IPv6 / UDP / dst-port 547.
	if err := attachDHCPv6Filter(rawFd); err != nil {
		_ = syscall.Close(rawFd)
		_ = c.Close()
		return nil, fmt.Errorf("failed to attach BPF filter: %w", err)
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
			// ENOBUFS: kernel dropped frames because the socket receive buffer
			// was full (e.g. a burst of DHCPv6 packets).  Log and continue —
			// this is transient and does not warrant tearing down the listener.
			if errors.Is(err, syscall.ENOBUFS) {
				ll.Warnf("Listen %s: receive buffer overflow, frame(s) dropped", l.ifi.Name)
				continue
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

// dhcpv6FilterInstructions returns the classic BPF instructions that select
// only IPv6/UDP frames destined for DHCPv6 server port 547.
//
// Frame layout assumed (no 802.1Q VLAN tag):
//
//	[12:14] EtherType (must be 0x86DD for IPv6)
//	[20]    IPv6 next-header (byte 6 of the 40-byte IPv6 header)
//	[56:58] UDP destination port (14 + 40 + 2)
func dhcpv6FilterInstructions() []bpf.Instruction {
	return []bpf.Instruction{
		// 0: load EtherType halfword
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 1: drop if not IPv6 (0x86DD)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 5},
		// 2: load IPv6 next-header byte
		bpf.LoadAbsolute{Off: 20, Size: 1},
		// 3: drop if not UDP (17)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 3},
		// 4: load UDP destination port halfword
		bpf.LoadAbsolute{Off: 56, Size: 2},
		// 5: accept if dst port == 547, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dhcpv6.DefaultServerPort), SkipTrue: 0, SkipFalse: 1},
		// 6: accept — return full packet length
		bpf.RetConstant{Val: 0xFFFF},
		// 7: drop — return 0
		bpf.RetConstant{Val: 0},
	}
}

// attachDHCPv6Filter installs a classic BPF filter on fd that passes only
// IPv6/UDP frames destined for DHCPv6 server port 547 (0x0223).
func attachDHCPv6Filter(fd int) error {
	insts, err := bpf.Assemble(dhcpv6FilterInstructions())
	if err != nil {
		return fmt.Errorf("bpf assemble: %w", err)
	}

	filters := make([]unix.SockFilter, len(insts))
	for i, ri := range insts {
		filters[i] = unix.SockFilter{Code: ri.Op, Jt: ri.Jt, Jf: ri.Jf, K: ri.K}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	return unix.SetsockoptSockFprog(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &prog)
}
