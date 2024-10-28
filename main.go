package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/vodafon/swork"
)

var (
	flagShow     = flag.Bool("show", false, "show only filtered")
	flagInternal = flag.Bool("int", false, "filter internal IPs")
	flagCF       = flag.Bool("cf", false, "filter CloudFlare IPs")
	flagS3       = flag.Bool("s3", false, "filter Amazone S3 IPs")
	flagProcs    = flag.Int("procs", 10, "concurrency")

	//go:embed ranges/internal.txt
	internalCidrs string
	//go:embed ranges/cloudflare.txt
	cloudflareCidrs string
	//go:embed ranges/s3.txt
	s3Cidrs string
)

type Processor struct {
	w       io.Writer
	show    bool
	filters []Filter
}

func (obj *Processor) Process(line string) {
	ip := net.ParseIP(line)
	filtered := false
	for _, filter := range obj.filters {
		filtered = filter.Filt(ip)
		if filtered {
			break
		}
	}
	if obj.show != filtered {
		return
	}
	fmt.Fprintf(obj.w, "%s\n", line)
}

type Filter interface {
	Filt(ip net.IP) bool
}

func main() {
	flag.Parse()
	if *flagProcs < 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	proc := &Processor{
		w:    os.Stdout,
		show: *flagShow,
	}

	if *flagInternal {
		proc.filters = append(proc.filters, NewInternalFilter(internalCidrs))
	}

	if *flagCF {
		proc.filters = append(proc.filters, NewCFFilter(cloudflareCidrs))
	}

	if *flagS3 {
		proc.filters = append(proc.filters, NewS3Filter(s3Cidrs))
	}

	process(proc)
}

func process(proc *Processor) {
	w := swork.NewWorkerGroup(*flagProcs, proc)

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		w.StringC <- sc.Text()
	}

	close(w.StringC)

	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	w.Wait()
}
