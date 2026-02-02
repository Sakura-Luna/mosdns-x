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

package dnsutils

import "codeberg.org/miekg/dns"

func IsEdnsResp(r *dns.Msg) bool {
	return r.UDPSize > 0 || r.IsEdns0()
}

// UpgradeEDNS0 enables EDNS0 for m and returns it's dns.OPT record.
// m must be a msg without dns.OPT.
func UpgradeEDNS0(m *dns.Msg) {
	m.UDPSize = 1232
	return
}

// RemoveEDNS0 removes the OPT record from m.
func RemoveEDNS0(m *dns.Msg) {
	m.UDPSize = 0
	m.Security = false
	m.CompactAnswers = false
	m.Delegation = false
	m.Pseudo = []dns.RR{}
	return
}

func RemoveEDNS0Option(m *dns.Msg, opt uint16) {
	ps := m.Pseudo
	for i, o := range ps {
		if dns.RRToCode(o.(dns.EDNS0)) == opt {
			m.Pseudo = append(ps[:i], ps[i+1:]...)
			return
		}
	}
	return
}

func GetEDNS0Option(m *dns.Msg, opt uint16) dns.EDNS0 {
	for _, o := range m.Pseudo {
		option := o.(dns.EDNS0)
		if dns.RRToCode(option) == opt {
			return option
		}
	}
	return nil
}
