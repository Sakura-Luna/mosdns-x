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

package padding

import (
	"context"

	"codeberg.org/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "padding"

func init() {
	coremain.RegNewPresetPluginFunc("_pad_query", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &PadQuery{BP: bp}, nil
	})
	coremain.RegNewPresetPluginFunc("_enable_conditional_response_padding", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &ResponsePaddingHandler{BP: bp}, nil
	})
	coremain.RegNewPresetPluginFunc("_enable_response_padding", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &ResponsePaddingHandler{BP: bp, Always: true}, nil
	})
}

var (
	_ coremain.ExecutablePlugin = (*PadQuery)(nil)
	_ coremain.ExecutablePlugin = (*ResponsePaddingHandler)(nil)
)

const (
	queryLen    = 128
	responseLen = 468
	maxPadLen   = 1232
)

type PadQuery struct {
	*coremain.BP
}

// Exec pads queries to 128 octets as RFC 8467 recommended.
func (p *PadQuery) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	q := qCtx.Q()
	if q.Len() <= 1152 {
		dnsutils.RemoveEDNS0Option(q, dns.CodePADDING)
		q.Pad(queryLen)
	} else {
		dnsutils.PadToMinimum(q, maxPadLen)
	}

	if err := executable_seq.ExecChain(ctx, qCtx, next); err != nil {
		return err
	}
	if r := qCtx.R(); r != nil {
		oq := qCtx.OriginalQuery()
		if !oq.IsEdns0() { // The original query does not have EDNS0
			dnsutils.RemoveEDNS0(r) // Remove EDNS0 from the response.
		} else {
			// If original query does not have Padding option.
			dnsutils.RemoveEDNS0Option(r, dns.CodePADDING)
		}
	}
	return nil
}

type ResponsePaddingHandler struct {
	*coremain.BP
	// Always indicates that ResponsePaddingHandler should always
	// pad response as long as it is EDNS0 even if it wasn't padded.
	Always bool
}

// Exec pads responses to 468 octets as RFC 8467 recommended.
func (h *ResponsePaddingHandler) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	if err := executable_seq.ExecChain(ctx, qCtx, next); err != nil {
		return err
	}

	oq := qCtx.OriginalQuery()
	if r := qCtx.R(); r != nil {
		if oq.IsEdns0() { // Only pad response if client supports EDNS0.
			// Only pad response if client padded its query unless force.
			if h.Always || dnsutils.GetEDNS0Option(oq, dns.CodePADDING) != nil {
				if r.Len() <= 936 {
					dnsutils.RemoveEDNS0Option(r, dns.CodePADDING)
					r.Pad(responseLen)
				} else {
					dnsutils.PadToMinimum(r, maxPadLen)
				}
			}
		}
	}
	return nil
}
