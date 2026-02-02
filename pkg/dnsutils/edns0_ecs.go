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

import (
	"net/netip"

	"codeberg.org/miekg/dns"
)

// RemoveECS removes the *dns.SUBNET record in m.
func RemoveECS(m *dns.Msg) {
	for i, opt := range m.Pseudo {
		if dns.RRToCode(opt.(dns.EDNS0)) == dns.CodeSUBNET {
			m.Pseudo = append(m.Pseudo[:i], m.Pseudo[i+1:]...)
			return
		}
	}
	return
}

func GetECS(m *dns.Msg) (e *dns.SUBNET) {
	for _, opt := range m.Pseudo {
		if dns.RRToCode(opt.(dns.EDNS0)) == dns.CodeSUBNET {
			return opt.(*dns.SUBNET)
		}
	}
	return nil
}

// AddECS adds ecs to opt.
func AddECS(m *dns.Msg, ecs *dns.SUBNET, overwrite bool) (newECS bool) {
	ps := m.Pseudo
	for i, opt := range ps {
		if dns.RRToCode(opt.(dns.EDNS0)) == dns.CodeSUBNET {
			if overwrite {
				m.Pseudo[i] = ecs
				return false
			}
			return false
		}
	}
	m.Pseudo = append(ps, ecs)
	return true
}

func NewEDNS0Subnet(ip netip.Addr, mask uint8, v6 bool) *dns.SUBNET {
	edns0Subnet := new(dns.SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if !v6 { // ipv4
		edns0Subnet.Family = 1
	} else { // ipv6
		edns0Subnet.Family = 2
	}

	edns0Subnet.Netmask = mask
	if !ip.IsValid() {
		panic("Invalid IP")
	}
	edns0Subnet.Address = ip

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	edns0Subnet.Scope = 0
	return edns0Subnet
}
