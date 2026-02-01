/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package fastforward

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/bundled_upstream"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/upstream"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const PluginType = "fast_forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*fastForward)(nil)

type fastForward struct {
	*coremain.BP
	args *Args

	upstreamWrappers []bundled_upstream.Upstream
	upstreamsCloser  []io.Closer
}

type Args struct {
	Upstream []*UpstreamConfig `yaml:"upstream"`
	CA        []string          `yaml:"ca"`
}

type UpstreamConfig struct {
	Addr           string `yaml:"addr"` // required
	DialAddr       string `yaml:"dial_addr"`
	Trusted        bool   `yaml:"trusted"` // Ignored by racing logic, kept for config compatibility
	Socks5         string `yaml:"socks5"`
	S5Username     string `yaml:"s5_username"`
	S5Password     string `yaml:"s5_password"`
	SoMark         int    `yaml:"so_mark"`
	BindToDevice   string `yaml:"bind_to_device"`
	IdleTimeout    int    `yaml:"idle_timeout"`
	MaxConns       int    `yaml:"max_conns"`
	EnablePipeline bool   `yaml:"enable_pipeline"`
	Bootstrap      string `yaml:"bootstrap"`
	Insecure       bool   `yaml:"insecure"`
	KernelTX       bool   `yaml:"kernel_tx"`
	KernelRX       bool   `yaml:"kernel_rx"`
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newFastForward(bp, args.(*Args))
}

func newFastForward(bp *coremain.BP, args *Args) (*fastForward, error) {
	if len(args.Upstream) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	f := &fastForward{
		BP:   bp,
		args: args,
	}

	var rootCAs *x509.CertPool
	if len(args.CA) != 0 {
		var err error
		rootCAs, err = utils.LoadCertPool(args.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca: %w", err)
		}
	}

	for _, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing server addr")
		}

		// Handle Experimental UDPME
		if strings.HasPrefix(c.Addr, "udpme://") {
			u := newUDPME(c.Addr[8:])
			f.upstreamWrappers = append(f.upstreamWrappers, u)
			// UDPME doesn't need closer as it creates connection per request
			continue
		}

		opt := &upstream.Opt{
			DialAddr:       c.DialAddr,
			Socks5:         c.Socks5,
			S5Username:     c.S5Username,
			S5Password:     c.S5Password,
			SoMark:         c.SoMark,
			BindToDevice:   c.BindToDevice,
			IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
			MaxConns:       c.MaxConns,
			EnablePipeline: c.EnablePipeline,
			Bootstrap:      c.Bootstrap,
			Insecure:       c.Insecure,
			RootCAs:        rootCAs,
			KernelTX:       c.KernelTX,
			KernelRX:       c.KernelRX,
			Logger:         bp.L(),
		}

		u, err := upstream.NewUpstream(c.Addr, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream: %w", err)
		}

		w := &upstreamWrapper{
			address: c.Addr,
			u:       u,
		}

		f.upstreamWrappers = append(f.upstreamWrappers, w)
		f.upstreamsCloser = append(f.upstreamsCloser, u)
	}

	return f, nil
}

type upstreamWrapper struct {
	address string
	u       upstream.Upstream
}

func (u *upstreamWrapper) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Compress = true
	return u.u.ExchangeContext(ctx, q)
}

func (u *upstreamWrapper) Address() string {
	return u.address
}

func (u *upstreamWrapper) Trusted() bool {
	return true
}

func (f *fastForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	err := f.exec(ctx, qCtx)
	if err != nil {
		return err
	}
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (f *fastForward) exec(ctx context.Context, qCtx *query_context.Context) (err error) {
	r, err := bundled_upstream.ExchangeParallel(ctx, qCtx, f.upstreamWrappers, f.L())
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return nil
}

func (f *fastForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		_ = u.Close() // Silently close during shutdown
	}
	return nil
}
