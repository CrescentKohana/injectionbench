package demo

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

var (
	markdownImageRe = regexp.MustCompile(`!\[[^\]]*\]\(https?://[^)]+\)`)
	htmlImageRe     = regexp.MustCompile(`(?i)<img\b[^>]*\bsrc\s*=\s*["']https?://[^"']+["'][^>]*>`)
)

// filterText is the hardened app's output filter: it redacts every encoded form of canary it
// recognises and strips any outbound image, deliberately leaving spelled-out or reversed
// leaks unfiltered (documented residual risk).
func filterText(s, canary string) string {
	s = redactCanary(s, canary)
	s = markdownImageRe.ReplaceAllString(s, "[image removed]")
	s = htmlImageRe.ReplaceAllString(s, "[image removed]")
	return s
}

func redactCanary(s, canary string) string {
	if canary == "" {
		return s
	}
	for _, form := range canaryForms(canary) {
		if form != "" {
			s = strings.ReplaceAll(s, form, "[REDACTED]")
		}
	}
	return s
}

func canaryForms(canary string) []string {
	raw := []byte(canary)
	return []string{
		canary,
		url.QueryEscape(canary),
		base64.StdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		strings.ToLower(hex.EncodeToString(raw)),
		strings.ToUpper(hex.EncodeToString(raw)),
	}
}
