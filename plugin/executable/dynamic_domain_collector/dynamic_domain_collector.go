package dynamic_domain_collector

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "dynamic_domain_collector"

type Args struct {
	FileName string `yaml:"file"`
}

type Collector struct {
	*coremain.BP
	fileName string
	seen     sync.Map    // Optimal for read-heavy workloads
	ch       chan string // Async buffer for batch file writing
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	c := &Collector{
		BP:       bp,
		fileName: a.FileName,
		ch:       make(chan string, 4096), // Buffer to absorb traffic bursts
	}

	// Initial Load: Normalize existing file data (one-time cost)
	f, err := os.Open(c.fileName)
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// Thorough cleaning for file data to ensure consistency
			d := strings.ToLower(strings.Trim(scanner.Text(), ". \t\n\r"))
			if d != "" {
				c.seen.Store(d, struct{}{})
			}
		}
		f.Close()
	}

	// Background worker for non-blocking disk I/O
	go c.asyncWriter()

	return c, nil
}

func (c *Collector) asyncWriter() {
	f, err := os.OpenFile(c.fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 64*1024)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case domain, ok := <-c.ch:
			if !ok {
				w.Flush()
				return
			}
			w.WriteString(domain)
			w.WriteByte('\n')
		case <-ticker.C:
			w.Flush()
		}
	}
}

func (c *Collector) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// Relying on Gatekeeper (misc_optm) for structure validation and lowercasing.
	raw := qCtx.Q().Question[0].Name

	// ZERO-ALLOCATION PATH:
	// TrimSuffix returns the original string if the suffix is missing.
	// Since misc_optm already lowercased the domain, this is effectively free.
	cleaned := strings.TrimSuffix(raw, ".")

	// ATOMIC LOOKUP:
	// LoadOrStore handles check-and-set in a single atomic-like operation.
	if _, loaded := c.seen.LoadOrStore(cleaned, struct{}{}); !loaded {
		select {
		case c.ch <- cleaned:
		default:
			// Buffer full: drop to ensure zero impact on DNS response latency
		}
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}
