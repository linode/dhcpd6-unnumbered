# dhcpv6d-unnumbered

### What is dhcpv6d-unnumbered?
- dhcpv6d-unnumbered is a stateless dhcpv6 server that looks at interface routes against an accepted prefix-filter and will handout dhcpv6 replies with the requested information.
- currently tested bootstrapping baremetal linodes using `UEFI HTTP IPv6` but could be extended for other use cases.

### How Does it Work?
- it listens on the dhcpv6 server multicast address on each interface 
- the interface is checked against a regex. only matching interfaces are handled (default tap.*_0), not matching are ignored completely
- if the interfaces matches are regex
	- routes for that interface are looked up.
    - a route that matches our accept-prefix filter is handed out in the IA_NA option
- if a boot-url is requested we hand out a file depending on the user class
  - currently tested is using the `UEFI IPv6 HTTP` from there you can handout an ipxe.efi with embedded chain.
    - Sample (Must compile with IPv6 enabled):
      ```
      #!ipxe
      
      ifconf -c ipv6
      # chain http://[2600:3c02::f03c:93ff:fe60:1d33]/boot2.php?mac=${mac}&domain=${domain}&uuid=${uuid}&manufacturer=${manufacturer}&product=${product}&serial=${serial}
      chain --autofree http://boot.netboot.xyz
      boot
      ```

### NOTES:
- Currently the server hands out ia_na non-temporary address, dns servers, domain-name, search domain, hostname.  RA's are still needed for the default gw, set a nd-prefix in the accepted prefix range with the offlink flag set, managed-flag set, and other config flag set.

### Usage:
```
dhcpv6d-unnumbered --help
```

### Example:
```
/dhcpv6d-unnumbered -regex "et1$" -accept-prefix "2600:3c03::/64" -multicast -loglevel debug  -http-url "http://[2600:3c02::f03c:93ff:fe60:1d33]/ipxe.efi"
```

### Build:
```
GOOS=LINUX go build
```
