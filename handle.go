package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	ll "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

func IsUsingUEFI(msg *dhcpv6.Message) bool {
	if archTypes := msg.Options.ArchTypes(); archTypes != nil {
		if archTypes.Contains(iana.EFI_BC) || archTypes.Contains(iana.EFI_X86_64) || archTypes.Contains(iana.EFI_X86_64_HTTP) {
			return true
		}
	}
	if opt := msg.GetOneOption(dhcpv6.OptionUserClass); opt != nil {
		optuc := opt.(*dhcpv6.OptUserClass)
		for _, uc := range optuc.UserClasses {
			if strings.Contains(string(uc), "EFI") {
				return true
			}
		}
	}
	return false
}

// logClientInfo logs detailed information about a DHCPv6 client request
// to help discriminate between different types of clients
func logClientInfo(msg *dhcpv6.Message, peer *net.UDPAddr, srcMAC net.HardwareAddr) {
	fields := ll.Fields{
		"msg_type": msg.Type().String(),
		"peer":     peer.IP.String(),
	}

	// Source MAC observed directly from the Ethernet frame header.
	if len(srcMAC) > 0 {
		fields["src_mac"] = srcMAC.String()
		fields["mac_locally_administered"] = isVirtualMAC(srcMAC)
	}

	// Client DUID (primary client identifier)
	if cid := msg.Options.ClientID(); cid != nil {
		fields["duid_type"] = fmt.Sprintf("%v", cid.Type)
		fields["hw_type"] = fmt.Sprintf("%v", cid.HwType)
		if len(cid.LinkLayerAddr) > 0 {
			fields["duid_mac"] = cid.LinkLayerAddr.String()
		}
		if cid.EnterpriseNumber != 0 {
			fields["enterprise_number"] = cid.EnterpriseNumber
		}
	}

	// Architecture types (e.g. UEFI, BIOS)
	if archTypes := msg.Options.ArchTypes(); archTypes != nil {
		fields["arch_types"] = fmt.Sprintf("%v", archTypes)
	}

	// User class
	if opt := msg.Options.GetOne(dhcpv6.OptionUserClass); opt != nil {
		fields["user_class"] = opt.String()
	}

	// Vendor class
	if opt := msg.Options.GetOne(dhcpv6.OptionVendorClass); opt != nil {
		fields["vendor_class"] = opt.String()
	}

	// Vendor-specific info
	if opt := msg.Options.GetOne(dhcpv6.OptionVendorOpts); opt != nil {
		fields["vendor_opts"] = opt.String()
	}

	// IANA
	if iana := msg.Options.OneIANA(); iana != nil {
		fields["iana_iaid"] = fmt.Sprintf("%v", iana.IaId)
	}

	// Requested options
	if ro := msg.Options.RequestedOptions(); len(ro) > 0 {
		fields["requested_options"] = fmt.Sprintf("%v", ro)
	}

	// Rapid commit
	if msg.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
		fields["rapid_commit"] = true
	}

	ll.WithFields(fields).Infof("handleMsg6: client identity dump")
}

// handleMsg is triggered every time there is a DHCPv6 request coming in.
func (l *Listener) HandleMsg6(buf []byte, oob *ipv6.ControlMessage, peer *net.UDPAddr, srcMAC net.HardwareAddr) {
	if oob.IfIndex != l.ifi.Index {
		ll.Errorf("handleMsg6: request not on listening socket....%d != %d", oob.IfIndex, l.ifi.Index)
		return
	}

	req, err := dhcpv6.FromBytes(buf)
	if err != nil {
		ll.Errorf("handleMsg6: error parsing dhcpv6 request: %v", err)
		return
	}
	msg, err := req.GetInnerMessage()
	if err != nil {
		ll.Errorf("handleMsg6: error getting inner message: %v", err)
		return
	}

	// Log client identity information for discrimination / debugging
	if ll.IsLevelEnabled(ll.DebugLevel) {
		logClientInfo(msg, peer, srcMAC)
	}

	// Ignore clients with locally-administered (virtual) source MAC addresses.
	// This filters out embedded processors like NVIDIA BlueField ECPF that
	// use software-assigned MACs on the host-facing link.
	if *flagIgnoreVirtualMAC {
		if len(srcMAC) == 0 || isVirtualMAC(srcMAC) {
			ll.Infof("handleMsg6: ignoring request from virtual MAC %s (peer %s) on %s",
				srcMAC, peer.IP, l.ifi.Name)
			return
		}
	}

	// Create a suitable basic response packet
	ll.Debugf("handleMsg6: received %s on %v", msg.Type(), l.ifi.Name)
	ll.Trace(req.Summary())

	ifiRoutes, err := getHostRoutesIPv6(l.ifi.Index)
	if err != nil {
		ll.Errorf("failed to get routes for interface %v: %v", l.ifi.Name, err)
		return
	}
	ll.Debugf("handleMsg6: routes found for interface %v: %v", l.ifi.Name, ifiRoutes)

	// seems like we have no host routes, not providing DHCP
	if ifiRoutes == nil {
		ll.Errorf("handleMsg6: we have no host routes for %s, not providing DHCP", l.ifi.Name)
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
	}
	if pickedIP == nil {
		ll.Errorf("handleMsg6: no routes matched in the accepted prefix range on %s", l.ifi.Name)
		return
	}

	ll.Debugf("handleMsg6: picked ip: %v", pickedIP)

	// mix DNS but mix em consistently so same IP gets the same order
	dns := mixDNS(pickedIP)

	fqdn := getHostname(l.ifi.Name, pickedIP)

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
		LinkLayerAddr: l.ifi.HardwareAddr,
		HwType:        iana.HWTypeEthernet,
	}

	if msg.Options.GetOne(dhcpv6.OptionIANA) != nil {
		clientIAID := msg.Options.OneIANA().IaId
		mods = append(mods, dhcpv6.WithIAID(clientIAID))
	}

	msg.Options.Add(&optIAAdress)

	blobURL := ""
	if IsUsingUEFI(msg) {
		if *flagUefiUrl != "" {
			blobURL = *flagUefiUrl
		}
	} else if *flagBiosUrl != "" {
		blobURL = *flagBiosUrl
	} else if *flagHTTPUrl != "" {
		blobURL = *flagHTTPUrl
	}

	mods = append(mods, dhcpv6.WithIANA(optIAAdress))
	mods = append(mods, dhcpv6.WithServerID(dhcpv6DUID))

	var resp dhcpv6.DHCPv6

	// Make sure we respond with the correct address
	switch msg.Type() {
	case dhcpv6.MessageTypeSolicit:
		if msg.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
			resp, err = dhcpv6.NewReplyFromMessage(msg, mods...)
			if err != nil {
				ll.Errorf("handleMsg6: failed building reply from solicit: %v", err)
				return
			}
		} else {
			resp, err = dhcpv6.NewAdvertiseFromSolicit(msg, mods...)
			if err != nil {
				ll.Errorf("handleMsg6: failed building advertise from solicit: %v", err)
				return
			}
		}
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew,
		dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeInformationRequest:
		resp, err = dhcpv6.NewReplyFromMessage(msg, mods...)
		if err != nil {
			ll.Errorf("handleMsg6: failed building reply: %v", err)
			return
		}
	default:
		ll.Errorf("handleMsg6: message type %d not supported", msg.Type())
		return
	}

	userClass := ""
	if msg.Options.GetOne(dhcpv6.OptionUserClass) != nil {
		userClass = msg.Options.GetOne(dhcpv6.OptionUserClass).String()
	}

	archTypes := msg.Options.ArchTypes()
	ll.Debugf("Found architecture %v", archTypes)

	ll.Debugf("handleMsg6: client requested %v", msg.Options.RequestedOptions())
	for _, code := range msg.Options.RequestedOptions() {
		switch code {
		case dhcpv6.OptionBootfileURL:
			if *flagiPXE != "" && strings.Contains(userClass, "iPXE") {
				bootOpt := dhcpv6.OptBootFileURL(*flagiPXE)
				resp.AddOption(bootOpt)
			} else if blobURL != "" {
				blobOpt := dhcpv6.OptBootFileURL(blobURL)
				resp.AddOption(blobOpt)
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
			resp.AddOption(&dhcpv6.OptFQDN{
				Flags: 0,
				DomainName: &rfc1035label.Labels{
					Labels: []string{fqdn},
				},
			})
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

	ll.Infof(
		"%s to %s on %s with %s, lease %gm, fqdn %s",
		resp.Type(),
		peer.IP,
		l.ifi.Name,
		pickedIP,
		optIAAdress.PreferredLifetime.Minutes(),
		fqdn,
	)
	ll.Trace(resp.Summary())

	if _, err := l.c.WriteTo(resp.ToBytes(), &ipv6.ControlMessage{IfIndex: oob.IfIndex}, peer); err != nil {
		ll.Warnf("handleMsg6: write to connection %v failed: %v", peer, err)
	}
}
