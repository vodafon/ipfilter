package main

import (
	"fmt"
	"net"
)

func NewInternalFilter() *InternalFilter {
	intF := InternalFilter{}
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		intF.privateIPBlocks = append(intF.privateIPBlocks, block)
	}
	return &intF
}

type InternalFilter struct {
	privateIPBlocks []*net.IPNet
}

func (obj *InternalFilter) Filt(ip net.IP) bool {
	return obj.IsPrivate(ip)
}

func (obj *InternalFilter) IsPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range obj.privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func NewCFFilter() *CFFilter {
	filt := CFFilter{}
	for _, cidr := range []string{
		// https://www.cloudflare.com/ips-v4
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/12",
		"172.64.0.0/13",
		"131.0.72.0/22",

		// https://www.cloudflare.com/ips-v6
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		filt.cfIPBlocks = append(filt.cfIPBlocks, block)
	}
	return &filt
}

type CFFilter struct {
	cfIPBlocks []*net.IPNet
}

func (obj *CFFilter) Filt(ip net.IP) bool {
	return obj.IsCF(ip)
}

func (obj *CFFilter) IsCF(ip net.IP) bool {
	for _, block := range obj.cfIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
