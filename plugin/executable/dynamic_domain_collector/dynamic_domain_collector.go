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
	ch       chan string // Async buffer
}

func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	c := &Collector{
		BP:       bp,
		fileName: a.FileName,
		ch:       make(chan string, 4096), // Larger buffer for bursts
	}

	// 1. Initial Load
	f, err := os.Open(c.fileName)
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if d := cleanDomain(scanner.Text()); d != "" {
				c.seen.Store(d, struct{}{})
			}
		}
		f.Close()
	}

	// 2. Optimized Async Writer with Batch Flush
	go c.asyncWriter()

	return c, nil
}

func (c *Collector) asyncWriter() {
	f, err := os.OpenFile(c.fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Use bufio to reduce syscalls (Issue #2)
	w := bufio.NewWriterSize(f, 64*1024)
	
	// Timer for periodic flush to ensure data is on disk even with low traffic
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
			
			// Auto-flush if buffer is getting full (handled by bufio internally)
			// or manual flush per batch if needed.
		case <-ticker.C:
			w.Flush()
		}
	}
}

func (c *Collector) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if q == nil || len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	domain := cleanDomain(q.Question[0].Name)
	if domain == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// FAST PATH: sync.Map.Load is lock-free and avoids cache-line contention
	if _, exists := c.seen.Load(domain); !exists {
		// SLOW PATH: Domain is new
		if _, loaded := c.seen.LoadOrStore(domain, struct{}{}); !loaded {
			// Non-blocking send to async writer
			select {
			case c.ch <- domain:
			default:
				// Buffer full: drop logging to protect DNS performance
			}
		}
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}
