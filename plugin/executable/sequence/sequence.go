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

package sequence

import (
	"context"
	"fmt"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"go.uber.org/zap"
)

const PluginType = "sequence"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	coremain.RegNewPresetPluginFunc("_return", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &_return{BP: bp}, nil
	})
}

type sequence struct {
	*coremain.BP

	ecs executable_seq.ExecChainNode
}

type Args struct {
	Exec any `yaml:"exec"`
}

func Init(bp *coremain.BP, args any) (p coremain.Plugin, err error) {
	return newSequencePlugin(bp, args.(*Args))
}

func newSequencePlugin(bp *coremain.BP, args *Args) (*sequence, error) {
	ecs, err := executable_seq.BuildExecutableLogicTree(args.Exec, bp.L(), bp.M().GetExecutables(), bp.M().GetMatchers())
	if err != nil {
		err = fmt.Errorf("cannot build sequence: %w", err)
		bp.L().Error("Init failed", zap.Error(err))
		return nil, err
	}

	return &sequence{
		BP:  bp,
		ecs: ecs,
	}, nil
}

func (s *sequence) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	if err := executable_seq.ExecChain(ctx, qCtx, s.ecs); err != nil {
		return err
	}

	return executable_seq.ExecChain(ctx, qCtx, next)
}

var _ coremain.ExecutablePlugin = (*_return)(nil)

type _return struct {
	*coremain.BP
}

func (n *_return) Exec(_ context.Context, _ *query_context.Context, _ executable_seq.ExecChainNode) error {
	return nil
}
