package judge

import (
	"context"
	"fmt"
)

type anyJudge struct {
	judges []Judge
}

// NewAny returns a Judge that succeeds if any of judges succeeds; its Score is the maximum
// across them, and it errors if any sub-judge errors.
func NewAny(judges ...Judge) Judge {
	return &anyJudge{judges: judges}
}

func (*anyJudge) Name() string { return "any" }

func (a *anyJudge) Evaluate(ctx context.Context, in Input) (Verdict, error) {
	var best Verdict
	hasBest := false
	success := false
	for _, j := range a.judges {
		v, err := j.Evaluate(ctx, in)
		if err != nil {
			return Verdict{}, fmt.Errorf("judge: any: %s: %w", j.Name(), err)
		}
		if v.Success {
			success = true
		}
		if !hasBest || v.Score > best.Score {
			best = v
			hasBest = true
		}
	}
	best.Success = success
	return best, nil
}
