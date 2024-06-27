package wildcards

import (
	"fmt"
	"testing"
)

func Test_generateWildcardPermutations(t *testing.T) {
	var tests = []struct {
		subdomain string
		domain    string
		expected  []string
	}{
		{"test", "example.com", []string{"*.example.com"}},
		{"abc.test", "example.com", []string{"*.example.com", "*.test.example.com"}},
		{"xyz.abc.test", "example.com", []string{"*.example.com", "*.test.example.com", "*.abc.test.example.com"}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s.%s", test.subdomain, test.domain), func(t *testing.T) {
			result := generateWildcardPermutations(test.subdomain, test.domain)
			if len(result) != len(test.expected) {
				t.Fatalf("expected %d permutations, got %d", len(test.expected), len(result))
			}
			for i, r := range result {
				if r != test.expected[i] {
					t.Fatalf("expected %s, got %s", test.expected[i], r)
				}
			}
		})
	}
}
