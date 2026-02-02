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

package responsematcher

import (
	"context"
	"io"
	"slices"

	"codeberg.org/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/matcher/elem"
	"github.com/pmkol/mosdns-x/pkg/matcher/msg_matcher"
	"github.com/pmkol/mosdns-x/pkg/matcher/netlist"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "response_matcher"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPresetPluginFunc("_valid_answer", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasValidAnswer{BP: bp}, nil
	})
	coremain.RegNewPresetPluginFunc("_valid_ip_answer", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasValidAnswer{BP: bp, strict: true}, nil
	})
	coremain.RegNewPresetPluginFunc("_empty_ip_answer", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasEmptyIPAnswer{BP: bp}, nil
	})
}

var _ coremain.MatcherPlugin = (*responseMatcher)(nil)

type Args struct {
	RCode []uint16 `yaml:"rcode"`
	IP    []string `yaml:"ip"`
	CNAME []string `yaml:"cname"`
}

type responseMatcher struct {
	*coremain.BP
	args *Args

	matcherGroup []executable_seq.Matcher
	closer       []io.Closer
}

func (m *responseMatcher) Match(ctx context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return executable_seq.LogicalAndMatcherGroup(ctx, qCtx, m.matcherGroup)
}

func (m *responseMatcher) Close() error {
	for _, closer := range m.closer {
		_ = closer.Close()
	}
	return nil
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newResponseMatcher(bp, args.(*Args))
}

func newResponseMatcher(bp *coremain.BP, args *Args) (m *responseMatcher, err error) {
	m = new(responseMatcher)
	m.BP = bp
	m.args = args

	if len(args.RCode) > 0 {
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewRCodeMatcher(elem.NewIntMatcher(args.RCode)))
	}

	if len(args.CNAME) > 0 {
		mg, err := domain.BatchLoadDomainProvider(
			args.CNAME,
			bp.M().GetDataManager(),
		)
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewCNameMatcher(mg))
		m.closer = append(m.closer, mg)
		bp.L().Info("cname matcher loaded", zap.Int("length", mg.Len()))
	}

	if len(args.IP) > 0 {
		l, err := netlist.BatchLoadProvider(args.IP, bp.M().GetDataManager())
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewAAAAAIPMatcher(l))
		m.closer = append(m.closer, l)
		bp.L().Info("ip matcher loaded", zap.Int("length", l.Len()))
	}

	return m, nil
}

type hasValidAnswer struct {
	*coremain.BP
	strict bool
}

var _ coremain.MatcherPlugin = (*hasValidAnswer)(nil)

func (e *hasValidAnswer) match(qCtx *query_context.Context) (matched bool) {
	r := qCtx.R()
	if r == nil {
		return false
	}

	q := qCtx.Q()

	type question struct {
		qType  uint16
		qClass uint16
	}

	if !e.strict {
		return slices.Contains([]uint16{0, 1, 3}, r.Rcode)
	}
	switch dns.RRToType(q.Question[0]) {
	case dns.TypeA, dns.TypeAAAA:
		m := make(map[question]struct{}, len(q.Question))
		for _, quest := range q.Question {
			m[question{dns.RRToType(quest), quest.Header().Class}] = struct{}{}
		}
		for _, rr := range r.Answer {
			q := question{dns.RRToType(rr), rr.Header().Class}
			if _, ok := m[q]; ok {
				return true
			}
		}
	}
	return false
}

func (e *hasValidAnswer) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return e.match(qCtx), nil
}

type hasEmptyIPAnswer struct {
	*coremain.BP
}

var _ coremain.MatcherPlugin = (*hasEmptyIPAnswer)(nil)

func (e *hasEmptyIPAnswer) match(qCtx *query_context.Context) (matched bool) {
	r := qCtx.R()
	if r == nil {
		return false
	}

	q := qCtx.Q()

	switch dns.RRToType(q.Question[0]) {
	case dns.TypeA, dns.TypeAAAA:
		for _, rr := range r.Answer {
			switch dns.RRToType(rr) {
			case dns.TypeA, dns.TypeAAAA:
				return false
			}
		}
	}
	return true
}

func (e *hasEmptyIPAnswer) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return e.match(qCtx), nil
}
