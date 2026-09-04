package timestress

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type jsonCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	Expected    string `json:"expected"` // "pass" | "fail"
}

func LoadCasesFromJSON(path string) ([]TestCase, error) {
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
		out = append(out, TestCase{
			Name:        c.Name,
			Description: c.Description,
			Count:       c.Count,
			ExpectKeys:  !strings.EqualFold(strings.TrimSpace(c.Expected), "fail"),
		})
	}
	return out, nil
}
