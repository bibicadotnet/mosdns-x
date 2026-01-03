/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package disable_ip_logging

import (
	"context"
	"net/netip"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "disable_ip_logging"

func init() {
	coremain.RegNewPersetPluginFunc("_disable_ip_logging", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &disableIPLogging{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*disableIPLogging)(nil)

type disableIPLogging struct {
	*coremain.BP
}

func (d *disableIPLogging) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// Clear client IP
	qCtx.ReqMeta().SetClientAddr(netip.Addr{})
	
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}
