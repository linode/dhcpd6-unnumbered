package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	ll "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	// MaxDatagram is the maximum length of message that can be received.
	MaxDatagram = 1 << 16
)

var (
	dns listIP

	flagLeaseTime = flag.Duration("leasetime", (30 * time.Minute), "DHCP lease time. aka Preffered Lifetime, Valid Lifetime x2")

	flagDynHost          = flag.Bool("dynamic-hostname", false, "dynamic hostname generated from {IP/./-}.domainname")
	flagHostnameOverride = flag.Bool(
		"hostname-override",
		false,
		"read hostname from <override-file-prefix + receiving interface name>, i.e. /var/lib/dhcpv6d-unnumbered/hostname.tap.XXXX_0",
	)
	flagHostnamePath = flag.String(
		"override-file-prefix",
		"/var/lib/dhcpv6d-unnumbered/hostname.",
		"path and file-prefix where to find hostname override files. I will concat this string with interface name request was received on to find a hostname override, if the file is missing we fall back to either dynamic or static hostname as appropriate",
	)
	flagHostname = flag.String(
		"hostname",
		"localhost",
		"static hostname to be handed out in dhcp offers, is ignored if dynamic-hostname is enabled",
	)
	flagDomainname = flag.String("domain-name", "local", "domainname to be handed out in dhcp offers")
	flagHTTPUrl    = flag.String("http-url", "", "url to serve UNDI http client (alias for bios-url)")
	flagiPXE       = flag.String("iPXE", "", "url to serve iPXE config (eg. boot.ipxe)")
	flagBiosUrl    = flag.String("bios-url", "", "url to serve UNDI http client")
	flagUefiUrl    = flag.String("uefi-url", "", "url to serve UEFI http client")

	logLevels = map[string]func(){
		"none":    func() { ll.SetOutput(ioutil.Discard) },
		"trace":   func() { ll.SetLevel(ll.TraceLevel) },
		"debug":   func() { ll.SetLevel(ll.DebugLevel) },
		"info":    func() { ll.SetLevel(ll.InfoLevel) },
		"warning": func() { ll.SetLevel(ll.WarnLevel) },
		"error":   func() { ll.SetLevel(ll.ErrorLevel) },
		"fatal":   func() { ll.SetLevel(ll.FatalLevel) },
	}
)

func main() {
	flagLogLevel := flag.String("loglevel", "info", fmt.Sprintf("Log level. One of %v", getLogLevels()))
	flag.Var(&dns, "dns", "dns server to use in DHCP offer, option can be used multiple times for more than 1 server")
	flagAcceptPrefix := flag.String("accept-prefix", "::/0", "IPv6 prefix to match host routes")
	flagIfiRegex := flag.String("regex", "eth.*", "regex to match interfaces.")
	flag.Parse()

	ll.SetFormatter(&ll.TextFormatter{
		FullTimestamp: true,
		PadLevelText:  true,
	})

	loglevel, ok := logLevels[*flagLogLevel]
	if !ok {
		ll.Fatalf("Invalid log level '%s'. Valid log levels are %v", *flagLogLevel, getLogLevels())
	}
	loglevel()

	ll.Infof("Setting log level to '%s'", ll.GetLevel())

	if *flagDynHost {
		ll.Infof("Dynamic hostnames based on IP enabled")
	}

	if *flagHostnameOverride {
		ll.Infof("Hostname override enabled from %s", *flagHostnamePath)
	}

	if len(dns) == 0 {
		err := dns.Set("2620:fe::9")
		if err != nil {
			ll.Fatalln("failed to set default DNS server")
		}
		ll.Infof("no DNS provided, using defaults")
	}
	ll.Infof("using DNS %v", dns)

	_, pfx, err := net.ParseCIDR(*flagAcceptPrefix)
	if err != nil {
		ll.Fatalf("unable to parse prefix: %v", err)
	}

	linksFeed := make(chan netlink.LinkUpdate, 10)
	linksDone := make(chan struct{})

	// lets hook into the netlink channel for push notifications from the kernel
	if err := netlink.LinkSubscribe(linksFeed, linksDone); err != nil {
		ll.Fatalf("unable to open netlink feed: %v", err)
	}

	// get existing list of links, in case we startup when vms are already active
	t, err := netlink.LinkList()
	if err != nil {
		ll.Fatalf("unable to get current list of links: %v", err)
	}

	e, err := NewEngine(*flagIfiRegex)
	if err != nil {
		ll.Fatalf("unable to get started: %v", err)
	}

	e.Flags.SetPrefix(pfx)

	// when starting up making sure any already existing interfaces are being handled and started
	for _, link := range t {

		ifName := link.Attrs().Name

		if !e.Qualifies(ifName) {
			ll.WithFields(ll.Fields{"Interface": ifName}).
				Debugf("%s did not qualify, skipping...", ifName)
			continue
		}

		if linkReady(link.Attrs()) {
			e.Add(link.Attrs().Index)
		}
	}

	// as we go on, detect any NIC changes from netlink and act accordingly
	for {
		select {
		case <-linksDone:
			ll.Fatalln("netlink feed ended")
		case link := <-linksFeed:
			ifName := link.Attrs().Name
			tapState := link.Attrs().OperState

			if !e.Qualifies(ifName) {
				ll.WithFields(ll.Fields{"Interface": ifName}).
					Debugf("%s did not qualify, skipping...", ifName)
				continue
			}

			ll.WithFields(ll.Fields{"Interface": ifName}).Tracef(
				"Netlink fired: %v, admin: %v, OperState: %v, Rx/Tx: %v/%v",
				ifName,
				link.Attrs().Flags&net.FlagUp,
				tapState,
				link.Attrs().Statistics.RxPackets,
				link.Attrs().Statistics.TxPackets,
			)

			tapExists := e.Exists(link.Attrs().Index)

			if !tapExists && linkReady(link.Attrs()) {
				e.Add(link.Attrs().Index)
			} else if tapExists && !linkReady(link.Attrs()) {
				e.Close(link.Attrs().Index)
			} else {
				ll.Tracef("%s Exists: %v, OperState: %s ... nothing to do?", ifName, tapExists, tapState)
			}
		}
	}

	/*
		// start server
		srv, err := StartListeners6()
		if err != nil {
			log.Fatal(err)
		}
		if err := srv.Wait(); err != nil {
			log.Print(err)
		}
	*/
}
