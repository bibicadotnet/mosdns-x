package executable_seq

import (
	"context"
	"fmt"
	"sync"

	"github.com/Knetic/govaluate"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

// ConditionNodeConfig is a config to build a ConditionNode.
type ConditionNodeConfig struct {
	If string `yaml:"if"`

	// See BuildExecutableLogicTree.
	Exec     interface{} `yaml:"exec"`
	ElseExec interface{} `yaml:"else_exec"`
}

// ConditionNode implement handler.ExecutableChainNode.
// Internal ConditionNode.ExecutableNode will also be linked by
// LinkPrevious and LinkNext.
type ConditionNode struct {
	ConditionMatcher   Matcher // if ConditionMatcher is nil, ConditionNode is a no-op.
	ExecutableNode     ExecutableChainNode
	ElseExecutableNode ExecutableChainNode

	next ExecutableChainNode
}

func (b *ConditionNode) Next() ExecutableChainNode {
	return b.next
}

func (b *ConditionNode) LinkNext(n ExecutableChainNode) {
	b.next = n
	if b.ExecutableNode != nil {
		LastNode(b.ExecutableNode).LinkNext(n)
	}
	if b.ElseExecutableNode != nil {
		LastNode(b.ElseExecutableNode).LinkNext(n)
	}
}

func ParseConditionNode(
	cfg *ConditionNodeConfig,
	logger *zap.Logger,
	execs map[string]Executable,
	matchers map[string]Matcher,
) (*ConditionNode, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	cn := new(ConditionNode)
	cm, err := newConditionMatcher(logger.Named("if"), cfg.If, matchers)
	if err != nil {
		return nil, err
	}
	cn.ConditionMatcher = cm

	if cfg.Exec != nil {
		cn.ExecutableNode, err = BuildExecutableLogicTree(cfg.Exec, logger.Named("exec"), execs, matchers)
		if err != nil {
			return nil, fmt.Errorf("failed to parse exec command: %w", err)
		}
	}
	if cfg.ElseExec != nil {
		cn.ElseExecutableNode, err = BuildExecutableLogicTree(cfg.ElseExec, logger.Named("else_exec"), execs, matchers)
		if err != nil {
			return nil, fmt.Errorf("failed to parse else_exec command: %w", err)
		}
	}

	return cn, nil
}

type conditionMatcher struct {
	lg           *zap.Logger
	expr         *govaluate.EvaluableExpression
	matchers     map[string]Matcher
	paramsPHPool sync.Pool
}

func newConditionMatcher(lg *zap.Logger, s string, matchers map[string]Matcher) (*conditionMatcher, error) {
	cm := &conditionMatcher{
		lg:           lg,
		matchers:     make(map[string]Matcher),
		paramsPHPool: sync.Pool{},
	}

	expr, err := govaluate.NewEvaluableExpression(s)
	if err != nil {
		return nil, err
	}

	cm.expr = expr
	vs := expr.Vars()
	for _, tag := range vs {
		m := matchers[tag]
		if m == nil {
			return nil, fmt.Errorf("cannot find matcher %s", tag)
		}
		cm.matchers[tag] = m
	}

	// params type check
	expr.ChecksTypes = true
	params := make(govaluate.MapParameters)
	for tag := range cm.matchers {
		params[tag] = true
	}
	if _, err := expr.Eval(params); err != nil {
		return nil, fmt.Errorf("invalid param, %w", err)
	}

	return cm, nil
}

type exprResult int

const (
	exprResultNull exprResult = iota
	exprResultFalse
	exprResultTrue
)

func (r exprResult) String() string {
	switch r {
	case exprResultNull:
		return "nil"
	case exprResultFalse:
		return "false"
	case exprResultTrue:
		return "true"
	default:
		return "invalid"
	}
}

type exprParamsPlaceHolder struct {
	ctx      context.Context
	qCtx     *query_context.Context
	matchers map[string]Matcher
	res      map[string]exprResult
}

// Reset clears internal maps to prevent data leakage between requests when reused from sync.Pool.
func (e *exprParamsPlaceHolder) Reset() {
	e.ctx = nil
	e.qCtx = nil
	e.matchers = nil
	for k := range e.res {
		delete(e.res, k)
	}
}

func newExprParamsPlaceHolder() *exprParamsPlaceHolder {
	return &exprParamsPlaceHolder{
		res: make(map[string]exprResult),
	}
}

func (e *exprParamsPlaceHolder) Get(name string) (interface{}, error) {
	// Optimization: Direct lookup and execution without closure allocation
	m, ok := e.matchers[name]
	if !ok {
		return nil, fmt.Errorf("cannot find matcher %s", name)
	}

	// Exec matcher
	res, err := m.Match(e.ctx, e.qCtx)
	if err != nil {
		return nil, err
	}

	if res {
		e.res[name] = exprResultTrue
	} else {
		e.res[name] = exprResultFalse
	}
	return res, nil
}

// A helper func for better log.
func (e *exprParamsPlaceHolder) makeResultZapFields(queryInfoField zap.Field, res bool) []zap.Field {
	o := make([]zap.Field, 2, len(e.res)+2)
	o[0] = queryInfoField
	o[1] = zap.Bool("result", res)
	for s, result := range e.res {
		o = append(o, zap.Stringer(s, result))
	}
	return o
}

func (m *conditionMatcher) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	paramsPH, ok := m.paramsPHPool.Get().(*exprParamsPlaceHolder)
	if !ok {
		paramsPH = newExprParamsPlaceHolder()
	} else {
		// Fix: reset maps to avoid side effects from previous requests
		paramsPH.Reset()
	}
	defer m.paramsPHPool.Put(paramsPH)

	// Optimization: Pass context and matchers directly to the placeholder
	paramsPH.ctx = ctx
	paramsPH.qCtx = qCtx
	paramsPH.matchers = m.matchers

	out, err := m.expr.Eval(paramsPH)
	if err != nil {
		return false, err
	}

	// Fix: safe type assertion with comma-ok to prevent panic
	res, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("condition expression '%s' returned non-boolean: %v", m.expr.String(), out)
	}

	m.lg.Debug(
		"condition matcher result",
		paramsPH.makeResultZapFields(qCtx.InfoField(), res)...,
	)
	return res, nil
}

func (b *ConditionNode) Exec(ctx context.Context, qCtx *query_context.Context, next ExecutableChainNode) (err error) {
	if b.ConditionMatcher != nil {
		ok, err := b.ConditionMatcher.Match(ctx, qCtx)
		if err != nil {
			return fmt.Errorf("matcher failed: %w", err)
		}
		if ok && b.ExecutableNode != nil {
			return ExecChainNode(ctx, qCtx, b.ExecutableNode)
		} else if !ok && b.ElseExecutableNode != nil {
			return ExecChainNode(ctx, qCtx, b.ElseExecutableNode)
		}
	}

	return ExecChainNode(ctx, qCtx, next)
}
