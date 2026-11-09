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

### Network boot for single-architecture racks:

Build the daemon for the CPU of the device running it (for example, x86-64
Destiny). The connected hosts' architectures are independent of the daemon's
architecture.

Each rack contains either ARM64 or x86-64 hosts. Configure the existing
`-uefi-url` with the image published for that rack's hosts. For example,
an ARM64 rack could use:

```
dhcpd6-unnumbered -regex "^et1$" -accept-prefix "2000:1234::/64" \
  -uefi-url "http://[2000:1234::1234]/arm64/ipxe.efi" \
  -iPXE "http://[2000:1234::1234]/boot.ipxe"
```

For an x86-64 rack, set `-uefi-url` to the published x86-64 image instead.
These are example URLs, not built-in paths.

The daemon does not choose or validate the image's CPU architecture. All clients
recognized as UEFI receive the same configured `-uefi-url`. ARM64 UEFI (11) and
ARM64 UEFI HTTP (19) are recognized alongside the existing x86-64 UEFI values.
This only distinguishes boot environments; rack configuration selects the image.
If the architecture option is absent, a user-class string containing `EFI` can
still identify UEFI. Other clients use `-bios-url`, or `-http-url` if unset.
UEFI clients do not fall back to those URLs if `-uefi-url` is empty.

Clients identifying as iPXE receive the configured `-iPXE` script URL first,
regardless of the UEFI URL. That script must load kernels and other boot artifacts
compatible with the rack's hosts. Configure a rack-specific script if necessary;
a shared script is suitable only if it handles both architectures correctly.
The boot files must be hosted separately; this daemon only advertises their URLs.

The boot/provisioning service defines the actual URLs when it publishes the
images and scripts. Obtain them from that service's deployment configuration,
then configure the ToR's persistent startup arguments (for example through RCM).
The daemon neither discovers URLs nor checks that they are reachable.
Publish the image and script before changing the rack's arguments, and verify
downloads and a real boot from a host on the boot network.

