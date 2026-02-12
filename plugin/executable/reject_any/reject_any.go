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

package rejectany

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "reject_any"

func init() {
	coremain.RegNewPresetPluginFunc("_reject_any", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &rejectAny{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*rejectAny)(nil)

type rejectAny struct {
	*coremain.BP
}

func (p *rejectAny) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	q := qCtx.Q()
	if dns.RRToType(q.Question[0]) != dns.TypeANY {
		return executable_seq.ExecChain(ctx, qCtx, next)
	}
	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	r.Answer = []dns.RR{
		&dns.HINFO{
			Hdr: dns.Header{
				Name:  q.Question[0].Header().Name,
				TTL:   8482,
				Class: dns.ClassINET,
			},
			HINFO: rdata.HINFO{
				Cpu: "ANY obsoleted",
				Os:  "See RFC 8482",
			},
		},
	}
	qCtx.SetResponse(r)
	return nil
}
