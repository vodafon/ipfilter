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

func NewS3Filter() *BlockFilter {
	filt := BlockFilter{}
	for _, cidr := range []string{
		// curl https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service=="S3") | .ip_prefix'
		"52.95.154.0/23",
		"52.219.64.0/22",
		"52.92.72.0/22",
		"3.5.16.0/21",
		"52.95.156.0/24",
		"3.5.208.0/22",
		"52.95.150.0/24",
		"52.219.60.0/23",
		"52.92.48.0/22",
		"52.92.0.0/20",
		"52.219.132.0/22",
		"52.95.170.0/23",
		"52.219.140.0/24",
		"52.95.142.0/23",
		"54.231.232.0/21",
		"54.222.52.0/22",
		"54.231.128.0/19",
		"52.218.128.0/17",
		"52.95.157.0/24",
		"108.175.52.0/22",
		"52.82.164.0/22",
		"54.231.0.0/17",
		"52.219.20.0/22",
		"52.219.24.0/21",
		"52.219.96.0/20",
		"52.219.72.0/22",
		"52.219.120.0/22",
		"54.222.48.0/22",
		"52.219.56.0/22",
		"52.95.174.0/24",
		"108.175.48.0/22",
		"54.231.248.0/22",
		"52.218.0.0/17",
		"52.219.44.0/22",
		"52.95.144.0/24",
		"52.95.176.0/24",
		"3.5.132.0/23",
		"52.92.16.0/20",
		"54.231.252.0/24",
		"52.219.0.0/20",
		"52.219.40.0/22",
		"52.219.136.0/22",
		"52.95.163.0/24",
		"52.95.145.0/24",
		"52.92.40.0/21",
		"52.219.32.0/21",
		"52.95.136.0/23",
		"52.219.48.0/22",
		"52.219.62.0/23",
		"52.95.175.0/24",
		"52.219.80.0/20",
		"52.95.148.0/23",
		"52.92.88.0/22",
		"3.5.0.0/20",
		"52.95.169.0/24",
		"52.95.164.0/23",
		"52.92.32.0/22",
		"52.95.172.0/23",
		"52.219.112.0/21",
		"52.219.16.0/22",
		"52.219.124.0/22",
		"3.5.128.0/22",
		"54.231.160.0/19",
		"52.92.76.0/22",
		"52.92.60.0/22",
		"52.219.68.0/22",
		"52.219.128.0/22",
		"52.95.146.0/23",
		"52.95.162.0/24",
		"52.95.128.0/21",
		"3.5.212.0/23",
		"52.95.138.0/24",
		"52.95.160.0/23",
		"52.95.158.0/23",
		"52.216.0.0/15",
		"52.82.188.0/22",
		"52.95.166.0/23",
		"52.95.168.0/24",
		"52.92.252.0/22",
		"54.231.192.0/20",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		filt.blocks = append(filt.blocks, block)
	}
	return &filt
}

func NewCFFilter() *BlockFilter {
	filt := BlockFilter{}
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
		filt.blocks = append(filt.blocks, block)
	}
	return &filt
}

type BlockFilter struct {
	blocks []*net.IPNet
}

func (obj *BlockFilter) Filt(ip net.IP) bool {
	return obj.IsInBlock(ip)
}

func (obj *BlockFilter) IsInBlock(ip net.IP) bool {
	for _, block := range obj.blocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
