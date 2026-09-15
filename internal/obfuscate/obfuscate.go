// Package obfuscate implements the text transforms InjectionBench uses to disguise attack
// payloads, and that the simulated model and hardened demo both know how to reverse or filter.
package obfuscate

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Apply transforms s according to transform, which must be "", "none", "base64", "fullwidth",
// "zerowidth" or "rot13".
func Apply(transform, s string) (string, error) {
	switch transform {
	case "", "none":
		return s, nil
	case "base64":
		return Base64(s), nil
	case "fullwidth":
		return FullWidth(s), nil
	case "zerowidth":
		return ZeroWidth(s), nil
	case "rot13":
		return ROT13(s), nil
	default:
		return "", fmt.Errorf("obfuscate: unknown transform %q", transform)
	}
}

// Base64 encodes s with standard base64.
func Base64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

const fullWidthOffset = 0xFEE0

// FullWidth folds printable ASCII to its Unicode full-width form (U+0021-U+007E -> +0xFEE0,
// space -> U+3000); other runes pass through unchanged.
func FullWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteRune('\u3000')
		case r >= '!' && r <= '~':
			b.WriteRune(r + fullWidthOffset)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ZeroWidth inserts U+200B between every pair of consecutive runes in s.
func ZeroWidth(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i, r := range runes {
		if i > 0 {
			b.WriteRune('\u200B')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ROT13 rotates ASCII letters by 13; every other rune is unchanged.
func ROT13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, s)
}
