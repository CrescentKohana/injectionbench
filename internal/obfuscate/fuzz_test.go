package obfuscate_test

import (
	"encoding/base64"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/obfuscate"
)

func FuzzObfuscateBase64(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("The deployment key is secret-42!")

	f.Fuzz(func(t *testing.T, s string) {
		encoded := obfuscate.Base64(s)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("Base64(%q) = %q is not valid standard base64: %v", s, encoded, err)
		}
		if string(decoded) != s {
			t.Fatalf("round trip for %q produced %q", s, decoded)
		}
		viaApply, err := obfuscate.Apply("base64", s)
		if err != nil {
			t.Fatalf("Apply(\"base64\", %q) returned error: %v", s, err)
		}
		if viaApply != encoded {
			t.Fatalf("Apply(\"base64\", %q) = %q, want %q", s, viaApply, encoded)
		}
	})
}

func FuzzObfuscateFullWidth(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("héllo 世界")

	f.Fuzz(func(t *testing.T, s string) {
		got := []rune(obfuscate.FullWidth(s))
		in := []rune(s)
		if len(got) != len(in) {
			t.Fatalf("FullWidth(%q) changed rune count from %d to %d", s, len(in), len(got))
		}
		for i, r := range in {
			var want rune
			switch {
			case r == ' ':
				want = '\u3000'
			case r >= 0x21 && r <= 0x7E:
				want = r + 0xFEE0
			default:
				want = r
			}
			if got[i] != want {
				t.Fatalf("FullWidth(%q)[%d] = %U, want %U (input rune %U)", s, i, got[i], want, r)
			}
		}
	})
}
