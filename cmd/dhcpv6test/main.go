// dhcpv6test sends DHCPv6 Solicit packets over raw Ethernet frames (AF_PACKET)
// so the source MAC is visible to dhcpd6-unnumbered exactly as it is in
// production.  Two cases are exercised:
//
//   - Normal (globally-unique) MAC  → expect Advertise / Reply
//   - Virtual (locally-administered) MAC → expect silence (ignored by server)
//
// Requires CAP_NET_RAW (run as root).
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

const (
	etherHeaderLen   = 14
	ipv6HeaderLen    = 40
	udpHeaderLen     = 8
	etherTypeIPv6    = 0x86DD
	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
)

func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }

// getLinkLocalAddr returns the first link-local IPv6 address on the interface.
// The server sends replies to this address, so we use it as the IPv6 source in
// every test frame regardless of the Ethernet source MAC being tested.
func getLinkLocalAddr(ifi *net.Interface) (net.IP, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return ip.To16(), nil
		}
	}
	return nil, fmt.Errorf("no link-local IPv6 address found on %s", ifi.Name)
}

// buildSolicit constructs a minimal DHCPv6 Solicit with the given MAC in its DUID.
func buildSolicit(mac net.HardwareAddr) []byte {
	duid := dhcpv6.Duid{
		Type:          dhcpv6.DUID_LL,
		HwType:        iana.HWTypeEthernet,
		LinkLayerAddr: mac,
	}
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dhcpv6.NewMessage: %v\n", err)
		os.Exit(1)
	}
	msg.MessageType = dhcpv6.MessageTypeSolicit
	msg.Options.Add(dhcpv6.OptClientID(duid))
	msg.Options.Add(&dhcpv6.OptIANA{
		IaId: [4]byte{mac[2], mac[3], mac[4], mac[5]},
	})
	msg.Options.Add(dhcpv6.OptRequestedOption(
		dhcpv6.OptionDNSRecursiveNameServer,
		dhcpv6.OptionDomainSearchList,
		dhcpv6.OptionFQDN,
	))
	return msg.ToBytes()
}

// udpChecksum computes the UDP checksum over the IPv6 pseudo-header.
// RFC 2460 §8.1: the pseudo-header contains src IP, dst IP, upper-layer
// packet length, and next-header, followed by the UDP segment itself.
func udpChecksum(srcIP, dstIP net.IP, udpSeg []byte) uint16 {
	// IPv6 pseudo-header (40 bytes) layout:
	//   [0:16]  source address
	//   [16:32] destination address
	//   [32:36] upper-layer packet length (32-bit, same value as UDP length field)
	//   [36:39] zeros (reserved)
	//   [39]    next-header (17 = UDP)
	// followed immediately by the UDP segment.
	pseudo := make([]byte, 40+len(udpSeg))
	copy(pseudo[0:16], srcIP)
	copy(pseudo[16:32], dstIP)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udpSeg)))
	pseudo[39] = 17 // next-header: UDP
	copy(pseudo[40:], udpSeg)

	// RFC 1071 one's-complement sum: accumulate 16-bit words.
	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	// If the payload has an odd number of bytes, pad the final byte on the
	// left (big-endian), i.e. treat it as the high byte of a 16-bit word.
	if len(pseudo)%2 != 0 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	// Fold the 32-bit accumulator down to 16 bits by adding the carry bits
	// (upper 16) back into the lower 16, repeating until no carry remains.
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	// One's complement: flip all bits. A receiver summing the segment
	// (including this checksum field) gets 0xffff if no errors occurred.
	return ^uint16(sum)
}

// buildEthernetFrame wraps a DHCPv6 payload inside UDP/IPv6/Ethernet destined
// for the DHCPv6 all-servers multicast address.
func buildEthernetFrame(srcMAC net.HardwareAddr, srcIP net.IP, payload []byte) []byte {
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	dstIP := dhcpv6.AllDHCPRelayAgentsAndServers.To16()
	udpLen := udpHeaderLen + len(payload)
	frame := make([]byte, etherHeaderLen+ipv6HeaderLen+udpLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)

	ip := frame[etherHeaderLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))
	ip[6] = 17  // next header: UDP
	ip[7] = 255 // hop limit
	copy(ip[8:24], srcIP)
	copy(ip[24:40], dstIP)

	udp := ip[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv6ClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(srcIP, dstIP, udp))
	return frame
}

// parseReply checks whether a received Ethernet frame is a DHCPv6
// Advertise or Reply addressed to ourIP on port 546.
func parseReply(frame []byte, ourIP net.IP) *dhcpv6.Message {
	if len(frame) < etherHeaderLen+ipv6HeaderLen+udpHeaderLen {
		return nil
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv6 {
		return nil
	}
	ip := frame[etherHeaderLen:]
	if ip[6] != 17 {
		return nil
	}
	if !net.IP(ip[24:40]).Equal(ourIP) {
		return nil
	}
	udp := ip[ipv6HeaderLen:]
	if len(udp) < udpHeaderLen {
		return nil
	}
	if binary.BigEndian.Uint16(udp[2:4]) != dhcpv6ClientPort {
		return nil
	}
	raw, err := dhcpv6.FromBytes(udp[udpHeaderLen:])
	if err != nil {
		return nil
	}
	msg, err := raw.GetInnerMessage()
	if err != nil {
		return nil
	}
	t := msg.Type()
	if t == dhcpv6.MessageTypeAdvertise || t == dhcpv6.MessageTypeReply {
		return msg
	}
	return nil
}

// runTest sends a Solicit from srcMAC/srcIP and waits up to timeout for a reply.
// Returns true when the outcome matches wantReply.
func runTest(ifi *net.Interface, srcIP net.IP, label string, mac net.HardwareAddr, wantReply bool, timeout time.Duration) bool {
	fmt.Printf("\n─── %s ───\n", label)
	fmt.Printf("  MAC:       %s  (locally-administered: %v)\n", mac, mac[0]&0x02 != 0)
	fmt.Printf("  IPv6 src:  %s\n", srcIP)
	fmt.Printf("  Expecting: ")
	if wantReply {
		fmt.Println("DHCPv6 Advertise / Reply")
	} else {
		fmt.Println("silence  (virtual MAC must be ignored by server)")
	}

	// Open the receive socket before sending to avoid a race.
	rfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IPV6)))
	if err != nil {
		fmt.Printf("  FAIL: open recv socket: %v\n", err)
		return false
	}
	defer syscall.Close(rfd) //nolint:errcheck
	if err := syscall.Bind(rfd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IPV6),
		Ifindex:  ifi.Index,
	}); err != nil {
		fmt.Printf("  FAIL: bind recv socket: %v\n", err)
		return false
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		fmt.Printf("  FAIL: set SO_RCVTIMEO: %v\n", err)
		return false
	}

	sfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IPV6)))
	if err != nil {
		fmt.Printf("  FAIL: open send socket: %v\n", err)
		return false
	}
	defer syscall.Close(sfd) //nolint:errcheck

	frame := buildEthernetFrame(mac, srcIP, buildSolicit(mac))
	if err := syscall.Sendto(sfd, frame, 0, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IPV6),
		Ifindex:  ifi.Index,
	}); err != nil {
		fmt.Printf("  FAIL: sendto: %v\n", err)
		return false
	}
	fmt.Println("  → Solicit sent")

	buf := make([]byte, 1<<16)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			break // EAGAIN / timeout
		}
		msg := parseReply(buf[:n], srcIP)
		if msg == nil {
			continue
		}
		offeredIP := "<no address in IANA>"
		if optIANA := msg.Options.OneIANA(); optIANA != nil {
			if a := optIANA.Options.OneAddress(); a != nil {
				offeredIP = a.IPv6Addr.String()
			}
		}
		if wantReply {
			fmt.Printf("  ← %s received — offered IP: %s\n", msg.Type(), offeredIP)
			fmt.Println("  PASS ✓")
			return true
		}
		fmt.Printf("  FAIL: unexpected %s received for virtual MAC\n", msg.Type())
		return false
	}

	if wantReply {
		fmt.Println("  FAIL: no reply within timeout")
		fmt.Println("        (is a /128 host route configured on the interface?)")
		return false
	}
	fmt.Println("  ← (silence) — virtual MAC correctly ignored")
	fmt.Println("  PASS ✓")
	return true
}

func main() {
	flagIfi := flag.String("interface", "", "interface to test on (required)")
	flagTimeout := flag.Duration("timeout", 3*time.Second, "per-test reply timeout")
	flag.Parse()

	if *flagIfi == "" {
		fmt.Fprintln(os.Stderr, "usage: dhcpv6test -interface <name> [-timeout 3s]")
		fmt.Fprintln(os.Stderr, "requires CAP_NET_RAW (run as root)")
		os.Exit(1)
	}

	ifi, err := net.InterfaceByName(*flagIfi)
	if err != nil {
		fmt.Fprintf(os.Stderr, "interface %q: %v\n", *flagIfi, err)
		os.Exit(1)
	}
	srcIP, err := getLinkLocalAddr(ifi)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tests := []struct {
		label     string
		mac       net.HardwareAddr
		wantReply bool
	}{
		{
			"Normal (globally-unique) MAC — server must reply",
			net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			true,
		},
		{
			"Virtual (locally-administered) MAC — server must ignore",
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			false,
		},
	}

	pass := 0
	for _, tc := range tests {
		if runTest(ifi, srcIP, tc.label, tc.mac, tc.wantReply, *flagTimeout) {
			pass++
		}
	}

	fmt.Printf("\n%d/%d tests passed\n", pass, len(tests))
	if pass != len(tests) {
		os.Exit(1)
	}
}
