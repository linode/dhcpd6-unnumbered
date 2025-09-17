FROM debian:bullseye
COPY dhcp6d-unnumbered /usr/sbin
EXPOSE 547/udp
ENTRYPOINT ["/usr/sbin/dhcp6d-unnumbered"]
