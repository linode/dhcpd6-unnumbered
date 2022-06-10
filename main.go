package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"

	ll "github.com/sirupsen/logrus"
)

const (
	// MaxDatagram is the maximum length of message that can be received.
	MaxDatagram = 1 << 16
)

var (
	regex        *regexp.Regexp
	acceptPrefix *net.IPNet
	dns          listIP

	flagIfiRegex     = flag.String("regex", "placeholder$", "regex to match interfaces.")
	flagUseMulticast = flag.Bool("multicast", false, "enable joining dhcpv6 multicast group")
	flagAcceptPrefix = flag.String(
		"accept-prefix",
		"",
		"IPv6 prefix to match host routes",
	)
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
	flagHTTPUrl    = flag.String("http-url", "", "url to serve uefi http client")
	flagiPXE       = flag.String("iPXE", "", "url to serve iPXE user-class")

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

	var err error
	regex, err = regexp.Compile(*flagIfiRegex)
	if err != nil {
		ll.Fatalf("unable to parse interface regex: %v", err)
	}

	ll.Infof("Handling Interfaces matching '%s'", regex.String())

	_, acceptPrefix, err = net.ParseCIDR(*flagAcceptPrefix)
	if err != nil {
		ll.Fatalf("unable to parse accept-prefix range: %v", err)
	}
	ll.Infof("accepting routes from %v", acceptPrefix)

	if len(dns) == 0 {
		err := dns.Set("2620:fe::9")
		if err != nil {
			ll.Fatalln("failed to set default DNS server")
		}
		ll.Infof("no DNS provided, using defaults")
	}
	ll.Infof("using DNS %v", dns)

	// start server
	srv, err := StartListeners6()
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Wait(); err != nil {
		log.Print(err)
	}
}
