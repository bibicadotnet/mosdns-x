package dynamic_domain_collector

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"

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
	mu       sync.RWMutex
	seen     map[string]struct{}
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
		seen:     make(map[string]struct{}),
	}

	f, err := os.Open(c.fileName)
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			d := cleanDomain(scanner.Text())
			if d != "" {
				c.seen[d] = struct{}{}
			}
		}
		f.Close()
	}

	return c, nil
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

	c.mu.RLock()
	_, exists := c.seen[domain]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		if _, stillExists := c.seen[domain]; !stillExists {
			f, err := os.OpenFile(c.fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()

				// Safe Append: Ensure file ends with newline before writing
				if info, errStat := f.Stat(); errStat == nil && info.Size() > 0 {
					if rf, errRef := os.Open(c.fileName); errRef == nil {
						lastByte := make([]byte, 1)
						if _, errRead := rf.ReadAt(lastByte, info.Size()-1); errRead == nil && lastByte[0] != '\n' {
							f.WriteString("\n")
						}
						rf.Close()
					}
				}

				if _, errWrite := f.WriteString(domain + "\n"); errWrite == nil {
					c.seen[domain] = struct{}{}
				}
			}
		}
		c.mu.Unlock()
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}
