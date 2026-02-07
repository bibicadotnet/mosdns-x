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
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

const PluginType = "dynamic_domain_collector"

type Args struct {
	FileName string `yaml:"file_name"`
}

type Collector struct {
	*coremain.BP
	fileName string
	mu       sync.RWMutex
	seen     map[string]struct{}
}

func getBaseDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")

	// Extract eTLD+1 (e.g., "google.co.uk" from "www.google.co.uk") using Mozilla's PSL
	base, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return base
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
			d := getBaseDomain(scanner.Text())
			if d != "" {
				c.seen[d] = struct{}{}
			}
		}
		if err := scanner.Err(); err != nil {
			bp.L().Warn("failed to scan domain file", zap.Error(err), zap.String("file", c.fileName))
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

	domain := getBaseDomain(q.Question[0].Name)
	if domain == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	c.mu.RLock()
	_, exists := c.seen[domain]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		// Double-check: ensure the domain wasn't added by another goroutine while waiting for the lock
		if _, stillExists := c.seen[domain]; !stillExists {
			f, err := os.OpenFile(c.fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()

				// Safe Append: verify if the existing file ends with a newline to prevent concatenation
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
