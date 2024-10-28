package main

import (
	"bytes"
	_ "embed"
	"testing"
)

var ips = []string{
	"52.208.161.129",
	"127.0.0.1",
	"95.158.146.79",
	"192.168.0.12",
	"104.16.52.111",
	"some invalid line",
	"34.247.128.79",
}

func TestHide(t *testing.T) {
	w := &bytes.Buffer{}
	proc := &Processor{
		w:    w,
		show: false,
	}
	proc.filters = append(proc.filters, NewInternalFilter(internalCidrs))
	proc.filters = append(proc.filters, NewCFFilter(cloudflareCidrs))

	for _, ip := range ips {
		proc.Process(ip)
	}

	exp := "52.208.161.129\n95.158.146.79\nsome invalid line\n34.247.128.79\n"
	res := w.String()

	if exp != res {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res)
	}
}

func TestShow(t *testing.T) {
	w := &bytes.Buffer{}
	proc := &Processor{
		w:    w,
		show: true,
	}
	proc.filters = append(proc.filters, NewInternalFilter(internalCidrs))
	proc.filters = append(proc.filters, NewCFFilter(cloudflareCidrs))

	for _, ip := range ips {
		proc.Process(ip)
	}

	exp := "127.0.0.1\n192.168.0.12\n104.16.52.111\n"
	res := w.String()

	if exp != res {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res)
	}
}
