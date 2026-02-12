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

package dual_selector

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type dummyNext struct {
	returnA     bool
	latencyA    time.Duration
	returnAAAA  bool
	latencyAAAA time.Duration
}

func (d *dummyNext) Exec(_ context.Context, qCtx *query_context.Context, _ executable_seq.ExecChainNode) error {
	q := qCtx.Q()
	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	question := q.Question[0]
	rrh := dns.Header{
		Name:  question.Header().Name,
		Class: question.Header().Class,
	}

	addr, _ := netip.ParseAddr("1.2.3.4")
	if dns.RRToType(question) == dns.TypeA && d.returnA {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: rrh,
			A:   rdata.A{Addr: addr},
		})
		time.Sleep(d.latencyA)
	}
	if dns.RRToType(question) == dns.TypeAAAA && d.returnAAAA {
		r.Answer = append(r.Answer, &dns.AAAA{
			Hdr:  rrh,
			AAAA: rdata.AAAA{Addr: addr},
		})
		time.Sleep(d.latencyAAAA)
	}
	qCtx.SetResponse(r)
	return nil
}

func TestSelector_Exec(t *testing.T) {
	nextNoA := executable_seq.WrapExecutable(&dummyNext{
		returnA:    false,
		returnAAAA: true,
	})
	nextNoAAAA := executable_seq.WrapExecutable(&dummyNext{
		returnA:    true,
		returnAAAA: false,
	})
	nextDual := executable_seq.WrapExecutable(&dummyNext{
		returnA:    true,
		returnAAAA: true,
	})
	nextLateA := executable_seq.WrapExecutable(&dummyNext{
		returnA:    true,
		latencyA:   time.Millisecond * 100,
		returnAAAA: true,
	})
	nextLateAAAA := executable_seq.WrapExecutable(&dummyNext{
		returnA:     true,
		returnAAAA:  true,
		latencyAAAA: time.Millisecond * 100,
	})

	tests := []struct {
		name      string
		mode      int
		qtype     uint16
		next      executable_seq.ExecChainNode
		wantErr   bool
		wantReply bool
	}{
		{
			name:      "prefer v4: do not block domain AAAA if domain does not have an A record",
			mode:      modePreferIPv4,
			qtype:     dns.TypeAAAA,
			next:      nextNoA,
			wantErr:   false,
			wantReply: true,
		},
		{
			name:      "prefer v4: do not block domain AAAA if A reply wasn't returned on time",
			mode:      modePreferIPv4,
			qtype:     dns.TypeAAAA,
			next:      nextLateA,
			wantErr:   false,
			wantReply: true,
		},
		{
			name:      "prefer v4: block domain AAAA if domain has A records",
			mode:      modePreferIPv4,
			qtype:     dns.TypeAAAA,
			next:      nextDual,
			wantErr:   false,
			wantReply: false,
		},
		{
			name:      "prefer v6: do not block domain A if domain does not have an AAAA record",
			mode:      modePreferIPv6,
			qtype:     dns.TypeA,
			next:      nextNoAAAA,
			wantErr:   false,
			wantReply: true,
		},
		{
			name:      "prefer v6: do not block domain A if AAAA reply wasn't returned on time",
			mode:      modePreferIPv6,
			qtype:     dns.TypeA,
			next:      nextLateAAAA,
			wantErr:   false,
			wantReply: true,
		},
		{
			name:      "prefer v6: block domain A if domain has AAAA records",
			mode:      modePreferIPv6,
			qtype:     dns.TypeA,
			next:      nextDual,
			wantErr:   false,
			wantReply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Selector{
				BP:          coremain.NewBP("", PluginType, nil, nil),
				mode:        tt.mode,
				waitTimeout: time.Millisecond * 20,
			}

			q := dns.NewMsg("example.", tt.qtype)
			qCtx := query_context.NewContext(q, nil)
			if err := s.Exec(context.Background(), qCtx, tt.next); (err != nil) != tt.wantErr {
				t.Errorf("Exec() error = %v, wantErr %v", err, tt.wantErr)
			}

			r := qCtx.R()
			if hasReply := msgAnsHasRR(r, tt.qtype); hasReply != tt.wantReply {
				t.Errorf("Exec() hasReply = %v, wantReply %v", hasReply, tt.wantReply)
			}
		})
	}
}
