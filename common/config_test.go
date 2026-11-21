package common

import (
	"testing"

	"gotest.tools/assert"
)

func TestParseKeyperHTTPURLs(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{"http://keyper-1:3000", []string{"http://keyper-1:3000"}},
		{"http://keyper-1:3000,https://keyper-2", []string{"http://keyper-1:3000", "https://keyper-2"}},
		{" http://keyper-1:3000 , https://keyper-2 ,", []string{"http://keyper-1:3000", "https://keyper-2"}},
		{"http://keyper-1:3000,,https://keyper-2", []string{"http://keyper-1:3000", "https://keyper-2"}},
		{"", []string{""}},
	}
	for _, c := range cases {
		urls, err := ParseKeyperHTTPURLs(c.value)
		assert.NilError(t, err, "value %q", c.value)
		got := make([]string, len(urls))
		for i, u := range urls {
			got[i] = u.String()
		}
		assert.DeepEqual(t, got, c.want)
	}
}

func TestParseKeyperHTTPURLsRejectsBadEntry(t *testing.T) {
	_, err := ParseKeyperHTTPURLs("http://keyper-1:3000,http://[::1")
	assert.ErrorContains(t, err, "missing ']' in host")
}
