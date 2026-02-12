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

package redirect

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "redirect"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*redirectPlugin)(nil)

type Args struct {
	Rule []string `yaml:"rule"`
}

type redirectPlugin struct {
	*coremain.BP
	m *domain.MatcherGroup[string]
}

func Init(bp *coremain.BP, args any) (p coremain.Plugin, err error) {
	return newRedirect(bp, args.(*Args))
}

func newRedirect(bp *coremain.BP, args *Args) (*redirectPlugin, error) {
	parseFunc := func(s string) (p, v string, err error) {
		f := strings.Fields(s)
		if len(f) != 2 {
			return "", "", fmt.Errorf("redirect rule must have 2 fields, but got %d", len(f))
		}
		return f[0], dnsutil.Fqdn(f[1]), nil
	}
	staticMatcher := domain.NewMixMatcher[string]()
	staticMatcher.SetDefaultMatcher(domain.MatcherFull)
	m, err := domain.BatchLoadProvider[string](
		args.Rule,
		staticMatcher,
		parseFunc,
		bp.M().GetDataManager(),
		func(b []byte) (domain.Matcher[string], error) {
			mixMatcher := domain.NewMixMatcher[string]()
			mixMatcher.SetDefaultMatcher(domain.MatcherFull)
			if err := domain.LoadFromTextReader[string](mixMatcher, bytes.NewReader(b), parseFunc); err != nil {
				return nil, err
			}
			return mixMatcher, nil
		},
	)
	if err != nil {
		return nil, err
	}
	bp.L().Info("redirect rules loaded", zap.Int("length", m.Len()))
	return &redirectPlugin{
		BP: bp,
		m:  m,
	}, nil
}

func (r *redirectPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Header().Class != dns.ClassINET {
		return executable_seq.ExecChain(ctx, qCtx, next)
	}

	orgQName := q.Question[0].Header().Name
	redirectTarget, ok := r.m.Match(orgQName)
	if !ok {
		return executable_seq.ExecChain(ctx, qCtx, next)
	}

	q.Question[0].Header().Name = redirectTarget
	err := executable_seq.ExecChain(ctx, qCtx, next)
	if r := qCtx.R(); r != nil {
		// Restore original query name.
		for i := range r.Question {
			if r.Question[i].Header().Name == redirectTarget {
				r.Question[i].Header().Name = orgQName
			}
		}

		// Insert a CNAME record.
		newAns := make([]dns.RR, 1, len(r.Answer)+1)
		newAns[0] = &dns.CNAME{
			Hdr: dns.Header{
				Name:  orgQName,
				Class: dns.ClassINET,
				TTL:   1,
			},
			CNAME: rdata.CNAME{Target: redirectTarget},
		}
		newAns = append(newAns, r.Answer...)
		r.Answer = newAns
	}
	return err
}

func (r *redirectPlugin) Close() error {
	_ = r.m.Close()
	return nil
}
