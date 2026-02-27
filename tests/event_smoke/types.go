package eventsmoke

import (
	"fmt"
	"sort"
	"strings"
)

type EventArg struct {
	Name   string `json:"name"`
	Op     string `json:"op"`
	Number string `json:"number,omitempty"`
	Bytes  string `json:"bytes,omitempty"`
}

type compileReq struct {
	Contract string     `json:"contract"`
	EventSig string     `json:"eventSig"`
	Args     []EventArg `json:"arguments"`
}

type registerReq struct {
	TriggerDefinition string `json:"triggerDefinition"`
	IdentityPrefix    string `json:"identityPrefix"`
	TTL               uint64 `json:"ttl"`
}

type TestCase struct {
	Name        string
	Description string
	Event       string
	Args        []EventArg
	EmitSig     string
	EmitArg     []string
	ExpectKey   bool
}

type Result struct {
	Name   string
	Status string
	Reason string
}

func FilterCases(all []TestCase, filter string) ([]TestCase, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return all, nil
	}

	want := map[string]bool{}
	for _, part := range strings.Split(filter, ",") {
		k := strings.TrimSpace(part)
		if k != "" {
			want[k] = true
		}
	}

	out := make([]TestCase, 0, len(all))
	for _, tc := range all {
		if want[tc.Name] {
			out = append(out, tc)
			delete(want, tc.Name)
		}
	}

	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for k := range want {
			missing = append(missing, k)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("unknown CASES entries: %s", strings.Join(missing, ","))
	}
	return out, nil
}