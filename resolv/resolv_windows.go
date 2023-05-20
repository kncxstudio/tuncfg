//go:build windows
// +build windows

package resolv

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func newHandler(name string, dnsServers []net.IP, dnsSuffixes []string, _ bool) (*Handler, error) {
	h := &Handler{
		name:        name,
		dnsServers:  dnsServers,
		dnsSuffixes: dnsSuffixes,
	}

	if err := h.getDefaultDNSOpts(); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Handler) getDefaultDNSOpts() error {
	ifcs, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %v", err)
	}

	for _, ifc := range ifcs {
		if ifc.Name == h.name {
			continue
		}
		luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
		if err != nil {
			return err
		}
		dns, err := luid.DNS()
		if err != nil {
			return err
		}

		// add only unique IP addresses
		for _, ip := range dns {
			ipByes := ip.As4()
			v := net.IPv4(ipByes[0], ipByes[1], ipByes[2], ipByes[3])
			if v == nil {
				// TODO: support IPv6 in future
				continue
			}
			add := true
			for _, orig := range h.origDnsServers {
				if v.Equal(orig) {
					add = false
				}
			}
			if add {
				h.origDnsServers = append(h.origDnsServers, v)
			}
		}
	}

	return nil
}

func (h *Handler) Set() error {
	if len(h.dnsServers) == 0 && len(h.dnsSuffixes) == 0 {
		// nothing to do
		return nil
	}

	luid, err := winipcfg.LUIDFromIndex(uint32(h.iface.Index))
	if err != nil {
		return err
	}

	dnsServers := make([]netip.Addr, 0)
	for _, v := range h.origDnsServers {
		dnsServers = append(dnsServers, netip.MustParseAddr(v.String()))
	}

	err = luid.SetDNS(windows.AF_INET, dnsServers, h.dnsSuffixes)
	if err != nil {
		return fmt.Errorf("failed to set DNS on %s interface: %v", h.name, err)
	}

	return nil
}

func (h *Handler) Restore() {
	// nothing to do in windows, because DNS are interface based
}
