package main

import (
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

// handleMsg is triggered every time there is a DHCPv6 request coming in.
func (l *Listener) HandleMsg6(buf []byte, oob *ipv6.ControlMessage, peer *net.UDPAddr) {
	ifi, err := net.InterfaceByIndex(oob.IfIndex)
	if err != nil {
		ll.Errorf("Error getting request interface: %v", err)
		return
	}

	req, err := dhcpv6.FromBytes(buf)
	if err != nil {
		ll.Errorf("error parsing dhcpv6 request: %v", err)
		return
	}
	msg, err := req.GetInnerMessage()

	// Create a suitable basic response packet
	ll.Debugf("received %s on %v", msg.Type(), ifi.Name)
	ll.Trace(req.Summary())

	if !(l.Flags.regex.Match([]byte(ifi.Name))) {
		ll.Warnf("dchp request on interface %v is not accepted, ignoring", ifi.Name)
		return
	}

	if ifi.Flags&net.FlagUp != net.FlagUp {
		ll.Warnf("dchp request on a interface %v, which is down. that's not right, skipping...", ifi.Name)
		return
	}

	ifiRoutes, err := getHostRoutesIPv6(ifi.Name)
	if err != nil {
		ll.Errorf("failed to get routes for interface %v: %v", ifi.Name, err)
		return
	}
	ll.Debugf("routes found for interface %v: %v", ifi.Name, ifiRoutes)

	// seems like we have no host routes, not providing DHCP
	if ifiRoutes == nil {
		ll.Infof("seems like we have no host routes, not providing DHCP")
		return
	}

	// by default set the first IP in our return slice of routes
	var pickedIP net.IP
	for _, ip := range ifiRoutes {
		if l.Flags.prefix.Contains(ip.IP) {
			ll.Debugf("address %s picked", ip.IP.String())
			pickedIP = ip.IP
			break
		}
		ll.Warnf("no routes matched in the accepted prefix range on %s", ifi.Name)
		return
	}

	ll.Debugf("picked ip: %v", pickedIP)

	// mix DNS but mix em consistently so same IP gets the same order
	dns := mixDNS(pickedIP)

	// should I generate a dynamic hostname?
	hostname := *flagHostname
	domainname := *flagDomainname

	// find dynamic hostname if feature is enabled
	if *flagDynHost {
		hostname = getDynamicHostname(pickedIP)
	}

	// static hostname in a file (if exists) will supersede the dynamic hostname
	if *flagHostnameOverride {
		h, d, err := getHostnameOverride(ifi.Name)
		if err == nil {
			hostname = h
			if d != "" {
				domainname = d
			}
		} else {
			ll.Debugf("unable to get static hostname: %v", err)
		}
	}

	// lets go compile the response
	var mods []dhcpv6.Modifier

	// Options to attach to all Replies
	optIAAdress := dhcpv6.OptIAAddress{
		IPv6Addr:          pickedIP,
		PreferredLifetime: *flagLeaseTime,
		ValidLifetime:     *flagLeaseTime * 2,
	}
	dhcpv6DUID := dhcpv6.Duid{
		Type:          dhcpv6.DUID_LLT,
		Time:          uint32(time.Now().Unix()),
		LinkLayerAddr: ifi.HardwareAddr,
		HwType:        iana.HWTypeEthernet,
	}

	if msg.Options.GetOne(dhcpv6.OptionIANA) != nil {
		clientIAID := msg.Options.OneIANA().IaId
		mods = append(mods, dhcpv6.WithIAID(clientIAID))
	}

	msg.Options.Add(&optIAAdress)
	mods = append(mods, dhcpv6.WithIANA(optIAAdress))
	mods = append(mods, dhcpv6.WithServerID(dhcpv6DUID))

	var resp dhcpv6.DHCPv6

	// Make sure we respond with the correct address
	switch msg.Type() {
	case dhcpv6.MessageTypeSolicit:
		if msg.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
			resp, err = dhcpv6.NewReplyFromMessage(msg, mods...)
		} else {
			resp, err = dhcpv6.NewAdvertiseFromSolicit(msg, mods...)
		}
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew,
		dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeInformationRequest:
		resp, err = dhcpv6.NewReplyFromMessage(msg, mods...)
	default:
		ll.Errorf("handleMsg6: message type %d not supported", msg.Type())
	}

	ll.Debugf("handleMsg6: client requested %v", msg.Options.RequestedOptions())
	for _, code := range msg.Options.RequestedOptions() {
		switch code {
		case dhcpv6.OptionBootfileURL:
			if msg.Options.GetOne(dhcpv6.OptionUserClass) != nil {
				userClass := msg.Options.GetOne(dhcpv6.OptionUserClass)
				if strings.Contains(userClass.String(), "iPXE") {
					bootOpt := dhcpv6.OptBootFileURL(*flagiPXE)
					resp.AddOption(bootOpt)
				}
			} else if *flagHTTPUrl != "" {
				bootOpt := dhcpv6.OptBootFileURL(*flagHTTPUrl)
				resp.AddOption(bootOpt)
			}
		case dhcpv6.OptionVendorClass:
			dataString := []byte("HTTPClient")
			dataSlice := [][]byte{}
			dataSlice = append(dataSlice, dataString)
			vendorOpts := dhcpv6.OptVendorClass{
				EnterpriseNumber: 10,
				Data:             dataSlice,
			}
			resp.AddOption(&vendorOpts)
		case dhcpv6.OptionFQDN:
			fqdn := dhcpv6.OptFQDN{
				Flags: 0,
				DomainName: &rfc1035label.Labels{
					Labels: []string{*flagDomainname},
				},
			}
			resp.AddOption(&fqdn)
		case dhcpv6.OptionDNSRecursiveNameServer:
			resp.AddOption(dhcpv6.OptDNS(dns...))
		case dhcpv6.OptionDomainSearchList:
			searchDomain := &rfc1035label.Labels{
				Labels: []string{*flagDomainname},
			}
			resp.AddOption(dhcpv6.OptDomainSearchList(searchDomain))

		default:
			ll.Infof("handleMsg6: no match for option code: %v", code)
			continue
		}
	}

	woob := &ipv6.ControlMessage{IfIndex: oob.IfIndex}

	ll.Infof(
		"%s to %s on %s with %s, lease %gm, hostname %s.%s",
		resp.Type(),
		peer.IP,
		ifi.Name,
		pickedIP,
		optIAAdress.PreferredLifetime.Minutes(),
		hostname,
		domainname,
	)
	ll.Trace(resp.Summary())

	if _, err := l.c.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		ll.Warnf("handleMsg6: write to connection %v failed: %v", peer, err)
	}
}
