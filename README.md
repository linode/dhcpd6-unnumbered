# dhcpd6-unnumbered

### What is dhcpd6d-unnumbered?
- dhcpd6d-unnumbered is a stateless dhcpd6 server that looks at interface routes against an accepted prefix-filter and will handout dhcpd6 replies with the requested information.
- currently tested bootstrapping baremetal linodes using `UEFI HTTP IPv6` but could be extended for other use cases.

### How Does it Work?
- it listens on the dhcpd6 server multicast address on each interface 
- the interface is checked against a regex. only matching interfaces are handled (`default tap.*_0)`, not matching are ignored completely
- if the interfaces matches are regex
	- routes for that interface are looked up.
    - a route that matches our accept-prefix filter is handed out in the `IA_NA` option
- if a boot-url is requested we select a file using the client's architecture and user class
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
- Currently the server hands out `ia_na` non-temporary address, dns servers, domain-name, search domain, hostname.  RA's are still needed for the default gw, set a nd-prefix in the accepted prefix range with the offlink flag set, managed-flag set, and other config flag set.

### VLAN / 802.1Q:
Bind to a **VLAN sub-interface**, not the trunk. On a trunk, 802.1Q-tagged frames have EtherType `0x8100` and are invisible to the raw socket — the daemon receives nothing.
```
dhcpd6-unnumbered -regex "^eth0\.100$" ...   # correct
dhcpd6-unnumbered -regex "^eth0$" ...        # broken if eth0 is a trunk
```

### Usage:
```
dhcpd6-unnumbered -help
```

### Example:
```
/dhcpd6d-unnumbered -regex "et1$" -accept-prefix "2000:1234::/64" -loglevel debug  -http-url "http://[2000:1234::1234]/ipxe.efi"
```

### Build:
```
GOOS=LINUX go build
```

### Architecture-aware network boot:

```
dhcpd6-unnumbered -regex "^et1$" -accept-prefix "2000:1234::/64" \
  -uefi-arm64-url "http://[2000:1234::1234]/arm64/ipxe.efi" \
  -uefi-x86_64-url "http://[2000:1234::1234]/x86_64/ipxe.efi" \
  -iPXE "http://[2000:1234::1234]/boot.ipxe"
```

DHCPv6 option 61 selects the ARM64 UEFI (11/19) or x86-64 UEFI (7/16)
image, respecting the client's architecture preference order. If architecture
is absent, the configured x86-64 URL is used. This is a default, not CPU detection.

`-uefi-url` remains the fallback when an architecture-specific UEFI URL is unset.
Without the new flags, existing UEFI/BIOS behavior is unchanged.
`-iPXE` still takes priority for iPXE clients; its script must support the
requesting host's architecture. Host the images separately at your chosen URLs;
the daemon only advertises them and does not validate their contents.

