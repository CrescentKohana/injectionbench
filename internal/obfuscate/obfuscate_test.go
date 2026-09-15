package obfuscate_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/obfuscate"
)

func TestBase64(t *testing.T) {
	got := obfuscate.Base64("hello world")
	want := base64.StdEncoding.EncodeToString([]byte("hello world"))
	if got != want {
		t.Errorf("Base64() = %q, want %q", got, want)
	}
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decoding Base64 output failed: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("round trip = %q, want %q", decoded, "hello world")
	}
}

func TestFullWidth(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ascii letters", "ABC", "\uFF21\uFF22\uFF23"},
		{"digit", "0", "\uFF10"},
		{"space maps to ideographic space", "a b", "\uFF41\u3000\uFF42"},
		{"non-ascii rune unchanged", "héllo", "\uFF48" + "é" + "\uFF4C\uFF4C\uFF4F"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := obfuscate.FullWidth(tt.in); got != tt.want {
				t.Errorf("FullWidth(%q) = %q (% X), want %q (% X)", tt.in, got, []rune(got), tt.want, []rune(tt.want))
			}
		})
	}
}

func TestFullWidthMappingPerRune(t *testing.T) {
	for r := rune(0x21); r <= 0x7E; r++ {
		got := []rune(obfuscate.FullWidth(string(r)))
		if len(got) != 1 || got[0] != r+0xFEE0 {
			t.Fatalf("FullWidth(%q) = %v, want single rune %U", string(r), got, r+0xFEE0)
		}
	}
}

func TestZeroWidth(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single rune unchanged", "a", "a"},
		{"two runes get separator", "ab", "a\u200Bb"},
		{"three runes", "abc", "a\u200Bb\u200Bc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := obfuscate.ZeroWidth(tt.in); got != tt.want {
				t.Errorf("ZeroWidth(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestZeroWidthRemovingMarksRecoversOriginal(t *testing.T) {
	in := "the deployment key is secret"
	got := obfuscate.ZeroWidth(in)
	recovered := strings.ReplaceAll(got, "\u200B", "")
	if recovered != in {
		t.Errorf("stripping U+200B from ZeroWidth output = %q, want %q", recovered, in)
	}
	if strings.Count(got, "\u200B") != len([]rune(in))-1 {
		t.Errorf("ZeroWidth inserted %d separators, want %d", strings.Count(got, "\u200B"), len([]rune(in))-1)
	}
}

func TestROT13(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lower", "abc", "nop"},
		{"upper", "XYZ", "KLM"},
		{"wraps alphabet", "hello", "uryyb"},
		{"non-letters unchanged", "a1! b", "n1! o"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := obfuscate.ROT13(tt.in); got != tt.want {
				t.Errorf("ROT13(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestROT13Involution(t *testing.T) {
	in := "The Deployment Key Is Secret 42!"
	twice := obfuscate.ROT13(obfuscate.ROT13(in))
	if twice != in {
		t.Errorf("ROT13 applied twice = %q, want original %q", twice, in)
	}
}

func TestApply(t *testing.T) {
	const payload = "the secret payload"
	tests := []struct {
		name      string
		transform string
		want      string
	}{
		{"empty transform is identity", "", payload},
		{"none is identity", "none", payload},
		{"base64", "base64", obfuscate.Base64(payload)},
		{"fullwidth", "fullwidth", obfuscate.FullWidth(payload)},
		{"zerowidth", "zerowidth", obfuscate.ZeroWidth(payload)},
		{"rot13", "rot13", obfuscate.ROT13(payload)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := obfuscate.Apply(tt.transform, payload)
			if err != nil {
				t.Fatalf("Apply(%q, ...) returned error: %v", tt.transform, err)
			}
			if got != tt.want {
				t.Errorf("Apply(%q, %q) = %q, want %q", tt.transform, payload, got, tt.want)
			}
		})
	}
}

func TestApplyUnknownTransform(t *testing.T) {
	for _, transform := range []string{"unknown", "BASE64", "Rot13", " base64"} {
		t.Run(transform, func(t *testing.T) {
			if _, err := obfuscate.Apply(transform, "x"); err == nil {
				t.Fatalf("Apply(%q, ...) returned nil error, want one", transform)
			}
		})
	}
}
