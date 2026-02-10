/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package ecs

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const PluginType = "ecs"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPersetPluginFunc("_no_ecs", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &noECS{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*ecsPlugin)(nil)

type Args struct {
	Auto           bool   `yaml:"auto"`
	ForceOverwrite bool   `yaml:"force_overwrite"`
	Mask4          int    `yaml:"mask4"` // default 24
	Mask6          int    `yaml:"mask6"` // default 48
	IPv4           string `yaml:"ipv4"`
	IPv6           string `yaml:"ipv6"`
}

func (a *Args) Init() error {
	if ok := utils.CheckNumRange(a.Mask4, 0, 32); !ok {
		return fmt.Errorf("invalid mask4 %d, should be 0~32", a.Mask4)
	}
	if ok := utils.CheckNumRange(a.Mask6, 0, 128); !ok {
		return fmt.Errorf("invalid mask6 %d, should be 0~128", a.Mask6)
	}
	utils.SetDefaultNum(&a.Mask4, 24)
	utils.SetDefaultNum(&a.Mask6, 48)
	return nil
}

type ecsPlugin struct {
	*coremain.BP
	args       *Args
	ipv4, ipv6 netip.Addr
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newPlugin(bp, args.(*Args))
}

func newPlugin(bp *coremain.BP, args *Args) (p *ecsPlugin, err error) {
	if err := args.Init(); err != nil {
		return nil, err
	}

	ep := &ecsPlugin{
		BP:   bp,
		args: args,
	}

	if args.IPv4 != "" {
		addr, err := netip.ParseAddr(args.IPv4)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv4 address %s: %w", args.IPv4, err)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("%s is not an ipv4 address", args.IPv4)
		}
		ep.ipv4 = addr
	}

	if args.IPv6 != "" {
		addr, err := netip.ParseAddr(args.IPv6)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv6 address %s: %w", args.IPv6, err)
		}
		if !addr.Is6() {
			return nil, fmt.Errorf("%s is not an ipv6 address", args.IPv6)
		}
		ep.ipv6 = addr
	}

	return ep, nil
}

func (e *ecsPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	upgraded, newECS := e.addECS(qCtx)
	
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err != nil {
		return err
	}

	if r := qCtx.R(); r != nil {
		if upgraded {
			dnsutils.RemoveEDNS0(r)
		} else if newECS {
			dnsutils.RemoveMsgECS(r)
		}
	}
	return nil
}

func (e *ecsPlugin) addECS(qCtx *query_context.Context) (upgraded bool, newECS bool) {
	q := qCtx.Q()
	if q == nil {
		return false, false
	}

	opt := q.IsEdns0()
	if opt != nil && dnsutils.GetECS(opt) != nil && !e.args.ForceOverwrite {
		return false, false
	}

	var ecs *dns.EDNS0_SUBNET
	if e.args.Auto {
		clientAddr := qCtx.ReqMeta().GetClientAddr()
		if !clientAddr.IsValid() {
			return false, false
		}
		ecs = e.genECS(clientAddr)
	} else if len(q.Question) > 0 {
		qtype := q.Question[0].Qtype
		switch qtype {
		case dns.TypeA:
			if e.ipv4.IsValid() {
				ecs = e.genECS(e.ipv4)
			} else if e.ipv6.IsValid() {
				ecs = e.genECS(e.ipv6)
			}
		case dns.TypeAAAA:
			if e.ipv6.IsValid() {
				ecs = e.genECS(e.ipv6)
			} else if e.ipv4.IsValid() {
				ecs = e.genECS(e.ipv4)
			}
		}
	}

	if ecs != nil {
		if opt == nil {
			upgraded = true
			opt = dnsutils.UpgradeEDNS0(q)
		}
		newECS = dnsutils.AddECS(opt, ecs, true)
		return upgraded, newECS
	}
	return false, false
}

// genECS generates an ECS record with extreme performance.
// It uses a stack-allocated buffer for bit-masking to avoid heap allocations
// during the processing phase.
func (e *ecsPlugin) genECS(addr netip.Addr) *dns.EDNS0_SUBNET {
	var mask int
	var isV6 bool
	var buf [16]byte // Stack buffer: 0ns allocation
	var n int

	if addr.Is4() || addr.Is4In6() {
		mask = e.args.Mask4
		isV6 = false
		a4 := addr.Unmap().As4()
		n = copy(buf[:], a4[:])
	} else {
		mask = e.args.Mask6
		isV6 = true
		a16 := addr.As16()
		n = copy(buf[:], a16[:])
	}

	// Fast Bit-masking: Clean dirty bits after the subnet mask.
	// This ensures cache-key consistency (Normalization).
	fullBytes := mask / 8
	if fullBytes < n {
		if rem := mask % 8; rem > 0 {
			buf[fullBytes] &= byte(0xFF << (8 - rem))
			fullBytes++
		}
		// Zero out tailing bytes using a fast loop.
		for i := fullBytes; i < n; i++ {
			buf[i] = 0
		}
	}

	// Pass the temporary stack slice to NewEDNS0Subnet.
	// NewEDNS0Subnet is responsible for making a safe heap copy.
	return dnsutils.NewEDNS0Subnet(buf[:n], uint8(mask), isV6)
}

type noECS struct {
	*coremain.BP
}

var _ coremain.ExecutablePlugin = (*noECS)(nil)

func (n *noECS) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if q := qCtx.Q(); q != nil {
		dnsutils.RemoveMsgECS(q)
	}

	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	
	if r := qCtx.R(); r != nil {
		dnsutils.RemoveMsgECS(r)
	}
	return err
}
