package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
)

// asrTolerance bounds how far a Rate's stored ASR may drift from Successes/Trials before
// ReadJSON rejects the report as inconsistent (hand-edited or otherwise corrupted).
const asrTolerance = 1e-9

// WriteJSON writes r as indented JSON followed by a trailing newline.
func WriteJSON(w io.Writer, r Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("report: encode: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("report: write: %w", err)
	}
	return nil
}

// ReadJSON decodes a Report, rejecting a document whose Tool is not ToolName or whose any Rate is
// internally inconsistent (negative or out-of-range counts, or a stored asr that does not match
// successes/trials within asrTolerance).
func ReadJSON(rd io.Reader) (Report, error) {
	var r Report
	if err := json.NewDecoder(rd).Decode(&r); err != nil {
		return Report{}, fmt.Errorf("report: decode: %w", err)
	}
	if r.Tool != ToolName {
		return Report{}, fmt.Errorf("report: tool %q is not %q", r.Tool, ToolName)
	}
	if err := validateRate(r.Overall); err != nil {
		return Report{}, fmt.Errorf("report: overall: %w", err)
	}
	for name, rate := range r.Categories {
		if err := validateRate(rate); err != nil {
			return Report{}, fmt.Errorf("report: category %s: %w", name, err)
		}
	}
	for _, a := range r.Attacks {
		if err := validateRate(a.Rate); err != nil {
			return Report{}, fmt.Errorf("report: attack %s: %w", a.ID, err)
		}
	}
	return r, nil
}

func validateRate(r Rate) error {
	if r.Trials < 0 {
		return fmt.Errorf("rate has negative trials %d", r.Trials)
	}
	if r.Successes < 0 {
		return fmt.Errorf("rate has negative successes %d", r.Successes)
	}
	if r.Successes > r.Trials {
		return fmt.Errorf("rate has successes %d exceeding trials %d", r.Successes, r.Trials)
	}
	if math.Abs(r.ASR-rateASR(r)) > asrTolerance {
		return fmt.Errorf("rate asr %v does not match successes/trials %v", r.ASR, rateASR(r))
	}
	return nil
}
