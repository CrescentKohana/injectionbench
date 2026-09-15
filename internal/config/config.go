// Package config is the sole reader of process environment variables in InjectionBench.
package config

import "os"

// Config holds every externally configurable value InjectionBench needs.
type Config struct {
	TypeSafeAPIKey  string
	TypeSafeBaseURL string
	JevModel        string
	OpenAIBaseURL   string
	OpenAIAPIKey    string
	OpenAIModel     string
}

const (
	defaultTypeSafeBaseURL = "https://api.typesafe.ai"
	defaultJevModel        = "jev-latest"
	defaultOpenAIBaseURL   = "https://api.openai.com/v1"
	defaultOpenAIModel     = "gpt-4o-mini"
)

// Load builds a Config from lookup, falling back to documented defaults for empty values.
func Load(lookup func(string) (string, bool)) Config {
	return Config{
		TypeSafeAPIKey:  valueOrDefault(lookup, "TYPESAFE_API_KEY", ""),
		TypeSafeBaseURL: valueOrDefault(lookup, "TYPESAFE_BASE_URL", defaultTypeSafeBaseURL),
		JevModel:        valueOrDefault(lookup, "INJECTIONBENCH_JEV_MODEL", defaultJevModel),
		OpenAIBaseURL:   valueOrDefault(lookup, "OPENAI_BASE_URL", defaultOpenAIBaseURL),
		OpenAIAPIKey:    valueOrDefault(lookup, "OPENAI_API_KEY", ""),
		OpenAIModel:     valueOrDefault(lookup, "OPENAI_MODEL", defaultOpenAIModel),
	}
}

// FromEnv builds a Config from the process environment.
func FromEnv() Config {
	return Load(os.LookupEnv)
}

func valueOrDefault(lookup func(string) (string, bool), key, def string) string {
	if v, ok := lookup(key); ok && v != "" {
		return v
	}
	return def
}
