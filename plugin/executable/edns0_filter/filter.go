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

package edns0_filter

import (
	"context"

	"codeberg.org/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "edns0_filter"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPresetPluginFunc("_edns0_filter_no_edns0", func(bp *coremain.BP) (coremain.Plugin, error) {
		return NewFilter(bp, &Args{NoEDNS: true}), nil
	})
	coremain.RegNewPresetPluginFunc("_edns0_filter_ecs_only", func(bp *coremain.BP) (coremain.Plugin, error) {
		return NewFilter(bp, &Args{Keep: []uint16{dns.CodeSUBNET}}), nil
	})
}

type Args struct {
	// Args priority: NoEDNS > Keep > Discard.
	// If both Keep and Discard is not specified. edns0_filter will
	// keep no EDNS0 option (discard all EDNS0 options).
	NoEDNS  bool     `yaml:"no_edns"` // Remove entire EDNS0 RR.
	Keep    []uint16 `yaml:"accept"`  // Only keep those EDNS0 options and discard others.
	Discard []uint16 `yaml:"discard"` // Only remove those EDNS0 options and keep others.
}

var _ coremain.ExecutablePlugin = (*Filter)(nil)

type Filter struct {
	*coremain.BP
	args    *Args
	keep    map[uint16]struct{}
	discard map[uint16]struct{}
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return NewFilter(bp, args.(*Args)), nil
}

func NewFilter(bp *coremain.BP, args *Args) *Filter {
	newMapOrNil := func(opts []uint16) map[uint16]struct{} {
		if len(opts) == 0 {
			return nil
		}
		m := make(map[uint16]struct{})
		for _, option := range args.Keep {
			m[option] = struct{}{}
		}
		return m
	}

	return &Filter{
		BP:      bp,
		args:    args,
		keep:    newMapOrNil(args.Keep),
		discard: newMapOrNil(args.Discard),
	}
}

func (s *Filter) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	s.applyFilter(q)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (s *Filter) applyFilter(q *dns.Msg) {
	switch {
	case s.args.NoEDNS:
		dnsutils.RemoveEDNS0(q)
	case len(s.keep) > 0:
		if !q.IsEdns0() {
			break
		}
		ps := q.Pseudo
		edns0 := ps[:0]
		for _, rr := range ps {
			if _, accept := s.keep[dns.RRToCode(rr.(dns.EDNS0))]; accept {
				edns0 = append(edns0, rr)
			}
		}
		q.Pseudo = edns0
	case len(s.discard) > 0:
		if !q.IsEdns0() {
			break
		}
		ps := q.Pseudo
		edns0 := ps[:0]
		for _, rr := range ps {
			if _, remove := s.discard[dns.RRToCode(rr.(dns.EDNS0))]; !remove {
				edns0 = append(edns0, rr)
			}
		}
		q.Pseudo = edns0
	default: // remove all edns0 options
		if !q.IsEdns0() {
			break
		}
		dnsutils.RemoveEDNS0(q)
	}
}
