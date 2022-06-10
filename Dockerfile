FROM debian:bullseye
COPY dhcpv6d-unnumbered /usr/sbin
EXPOSE 547/udp
ENTRYPOINT ["/usr/sbin/dhcpv6d-unnumbered"]
