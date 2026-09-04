package timestress

import (
	"fmt"
	"sort"
	"strings"
)

type TestCase struct {
	Name        string
	Description string
	Count       int  // number of identities to register
	ExpectKeys  bool // whether all identities should receive a decryption key
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
