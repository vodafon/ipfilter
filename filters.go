package main

import (
	"fmt"
	"net"
	"strings"
)

func NewInternalFilter(cidrs string) *InternalFilter {
	intF := InternalFilter{}
	for _, cidr := range strings.Split(cidrs, "\n") {
		if cidr == "" || strings.HasPrefix(cidr, "//") {
			continue
		}
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("file internal.txt: parse error on %q: %v", cidr, err))
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

func NewS3Filter(cidrs string) *BlockFilter {
	// curl https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service=="S3") | .ip_prefix'
	return filterFromCidrs("s3.txt", cidrs)
}

func filterFromCidrs(fpath, cidrs string) *BlockFilter {
	filt := BlockFilter{}
	for _, cidr := range strings.Split(cidrs, "\n") {
		if cidr == "" || strings.HasPrefix(cidr, "//") {
			continue
		}
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("file %s: parse error on %q: %v", fpath, cidr, err))
		}
		filt.blocks = append(filt.blocks, block)
	}
	return &filt
}

func NewCFFilter(cidrs string) *BlockFilter {
	return filterFromCidrs("cloudflare.txt", cidrs)
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
