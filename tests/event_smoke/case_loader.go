package eventsmoke

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type jsonCase struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	EventSig    string     `json:"eventSig"`
	Args        []EventArg `json:"args"`
	EmitSig     string     `json:"emitSig"`
	EmitArgs    []string   `json:"emitArgs"`
	Expected    string     `json:"expected"` // "pass" | "fail"
}

var varRe = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

func LoadCasesFromJSON(path string, vars map[string]string) ([]TestCase, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cases file: %w", err)
	}

	var raw []jsonCase
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse cases json: %w", err)
	}

	out := make([]TestCase, 0, len(raw))
	for _, c := range raw {
		tc := TestCase{
			Name:        c.Name,
			Description: c.Description,
			Event:       expand(c.EventSig, vars),
			EmitSig:     expand(c.EmitSig, vars),
			EmitArg:     make([]string, 0, len(c.EmitArgs)),
			Args:        make([]EventArg, 0, len(c.Args)),
			ExpectKey:   !strings.EqualFold(strings.TrimSpace(c.Expected), "fail"),
		}
		for _, a := range c.EmitArgs {
			tc.EmitArg = append(tc.EmitArg, expand(a, vars))
		}
		for _, a := range c.Args {
			tc.Args = append(tc.Args, EventArg{
				Name:   expand(a.Name, vars),
				Op:     expand(a.Op, vars),
				Number: expand(a.Number, vars),
				Bytes:  expand(a.Bytes, vars),
			})
		}
		out = append(out, tc)
	}
	return out, nil
}

func expand(s string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := varRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		if v, ok := vars[sub[1]]; ok {
			return v
		}
		if v := os.Getenv(sub[1]); v != "" {
			return v
		}
		return m
	})
}