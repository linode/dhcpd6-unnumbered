package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

// getDynamicHostname will generate hostname from IP and predefined domainname
func getDynamicHostname(ip net.IP) string {
	return strings.ReplaceAll(ip.String(), ".", "-")
}

// getHostnameOverride returns a hoostname (and if applicable) a domainname read from a static file based on path+ifName
func getHostnameOverride(ifName string) (string, string, error) {
	h, err := os.ReadFile(*flagHostnamePath + ifName)
	if err != nil {
		return "", "", err
	}
	s := strings.SplitN(strings.TrimSpace(string(h)), ".", 2)
	if len(s) > 1 {
		return s[0], s[1], nil
	}
	return s[0], "", nil
}

// mixDNS sorts dns servers in a sudo-random way (the provided IP should always get back the same sequence of DNS)
func mixDNS(ip net.IP) []net.IP {
	l := len(dns)
	// just mod over last octet of IP as it provides the highest diversity without causing much complexity
	m := int(ip[len(ip)-1]) % l
	var mix []net.IP

	for i := 0; i < l; i++ {
		if i+m >= l {
			m = m - l
		}
		mix = append(mix, dns[i+m])
	}

	return mix
}

type listIP []net.IP

func (ip *listIP) String() string {
	var s string
	for _, i := range *ip {
		s = s + " " + i.String()
	}
	return s
}

func (ip *listIP) Set(value string) error {
	newIP := net.ParseIP(value)
	if newIP != nil {
		*ip = append(*ip, newIP)
		return nil
	}
	return fmt.Errorf("invalid ip: %v", value)
}

func getLogLevels() []string {
	var levels []string
	for k := range logLevels {
		levels = append(levels, k)
	}
	return levels
}

func getHostRoutesIPv6(ifName string) ([]*net.IPNet, error) {
	nlh, err := netlink.NewHandle()
	defer nlh.Delete()
	if err != nil {
		return nil, fmt.Errorf("unable to hook into netlink: %v", err)
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("unable to get link info: %v", err)
	}

	ro, err := nlh.RouteList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("unable to get routes: %v", err)
	}
	var r []*net.IPNet
	for _, d := range ro {
		m, l := d.Dst.Mask.Size()
		if m == 128 && l == 128 {
			r = append(r, d.Dst)
		}
	}
	return r, nil
}

// linkReady will return true when its ok to bind the ndp listener to it.
// it will wait for the TX counter to start incrementing since before thats the case
// there are certain aspects not fulfilled. (i.e. link local may not yet be assinged etc
// it will also help on edge cases where the interface is not yet fully provisioned even though up
func linkReady(l *netlink.LinkAttrs) bool {
	if l.OperState == 6 && l.Flags&net.FlagUp == net.FlagUp && l.Statistics.TxPackets > 0 {
		return true
	}
	return false
}
