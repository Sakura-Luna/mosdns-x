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

package executable_seq

import (
	"context"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

// Executable represents something that is executable.
type Executable interface {
	Exec(ctx context.Context, qCtx *query_context.Context, next ExecChainNode) error
}

// ExecChainNode represents a node in a executable chain.
type ExecChainNode interface {
	Executable
	LinkedListNode
}

// Matcher represents a matcher that can match a certain pattern in Context.
type Matcher interface {
	Match(ctx context.Context, qCtx *query_context.Context) (matched bool, err error)
}

// ExecutableNodeWrapper wraps a Executable to a ExecChainNode.
type ExecutableNodeWrapper struct {
	Executable
	NodeLinker
}

// WrapExecutable wraps a Executable to a ExecChainNode.
func WrapExecutable(e Executable) ExecChainNode {
	if ecn, ok := e.(ExecChainNode); ok {
		return ecn
	}
	return &ExecutableNodeWrapper{Executable: e}
}

type LinkedListNode interface {
	Next() ExecChainNode
	LinkNext(n ExecChainNode)
}

// NodeLinker implements LinkedListNode.
type NodeLinker struct {
	next ExecChainNode
}

func (l *NodeLinker) Next() ExecChainNode {
	return l.next
}

func (l *NodeLinker) LinkNext(n ExecChainNode) {
	l.next = n
}
