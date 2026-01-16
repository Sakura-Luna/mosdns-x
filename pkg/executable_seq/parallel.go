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
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type ParallelNode struct {
	s       []ExecutableChainNode
	timeout time.Duration

	logger *zap.Logger // not nil
}

const (
	parallelTimeout = time.Second * 3
)

type ParallelConfig struct {
	Parallel []interface{} `yaml:"parallel"`
}

func ParseParallelNode(c *ParallelConfig, logger *zap.Logger, execs map[string]Executable, matchers map[string]Matcher) (*ParallelNode, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	ps := make([]ExecutableChainNode, 0, len(c.Parallel))
	for i, subSequence := range c.Parallel {
		es, err := BuildExecutableLogicTree(subSequence, logger.Named("parallel_seq_"+strconv.Itoa(i)), execs, matchers)
		if err != nil {
			return nil, fmt.Errorf("invalid parallel command at index %d: %w", i, err)
		}
		ps = append(ps, es)
	}

	return &ParallelNode{
		s:      ps,
		logger: logger,
	}, nil
}

type parallelECSResult struct {
	qCtx *query_context.Context
	err  error
	from int
}

func (p *ParallelNode) Exec(ctx context.Context, qCtx *query_context.Context, next ExecutableChainNode) error {
	if err := p.exec(ctx, qCtx); err != nil {
		return err
	}
	return ExecChainNode(ctx, qCtx, next)
}

func (p *ParallelNode) exec(ctx context.Context, qCtx *query_context.Context) error {
	if len(p.s) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	c := make(chan *parallelECSResult, len(p.s)) // use buf chan to avoid blocking.

	var taskCtx context.Context
	var cancel context.CancelFunc

	if p.timeout > 0 {
		p.logger.Sugar().Warn("executing parallel command with timeout %v", p.timeout)
	}
	timeout := time.Now().Add(parallelTimeout)
	if ddl, ok := ctx.Deadline(); !ok || ddl.After(timeout) {
		taskCtx, cancel = context.WithDeadline(ctx, timeout)
	} else {
		taskCtx, cancel = context.WithTimeout(ctx, parallelTimeout)
	}
	defer cancel()

	for i, node := range p.s {
		i, node := i, node
		qCtxCopy := qCtx.Copy()

		wg.Add(1)
		go func() {
			defer wg.Done()
			pCtx, pCancel := context.WithCancel(taskCtx)
			defer pCancel()

			err := ExecChainNode(pCtx, qCtxCopy, node)
			select {
			case c <- &parallelECSResult{qCtx: qCtxCopy, err: err, from: i}:
			case <-pCtx.Done():
			}
		}()
	}

	return asyncWait(taskCtx, qCtx, p.logger, c, &wg, cancel)
}
