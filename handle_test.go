package main

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func TestIsUsingUEFI(t *testing.T) {
	tests := []struct {
		name      string
		archs     iana.Archs
		userClass string
		want      bool
	}{
		{name: "ARM64 UEFI", archs: iana.Archs{iana.EFI_ARM64}, want: true},
		{name: "ARM64 UEFI HTTP", archs: iana.Archs{iana.EFI_ARM64_HTTP}, want: true},
		{name: "ARM64 later in list", archs: iana.Archs{iana.UBOOT_ARM64, iana.EFI_ARM64}, want: true},
		{name: "x86-64 UEFI", archs: iana.Archs{iana.EFI_X86_64}, want: true},
		{name: "x86-64 UEFI HTTP", archs: iana.Archs{iana.EFI_X86_64_HTTP}, want: true},
		{name: "EFI user class without architecture", userClass: "EFI", want: true},
		{name: "ARM64 U-Boot is not UEFI", archs: iana.Archs{iana.UBOOT_ARM64}},
		{name: "BIOS", archs: iana.Archs{iana.INTEL_X86PC}},
		{name: "missing architecture"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeSolicit}
			if len(tt.archs) > 0 {
				msg.AddOption(dhcpv6.OptClientArchType(tt.archs...))
			}
			if tt.userClass != "" {
				msg.AddOption(&dhcpv6.OptUserClass{UserClasses: [][]byte{[]byte(tt.userClass)}})
			}
			msg, err := dhcpv6.MessageFromBytes(msg.ToBytes())
			if err != nil {
				t.Fatal(err)
			}
			if got := IsUsingUEFI(msg); got != tt.want {
				t.Errorf("IsUsingUEFI() = %t, want %t", got, tt.want)
			}
		})
	}
}
