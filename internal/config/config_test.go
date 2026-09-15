package config_test

import (
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/config"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	got := config.Load(lookupFrom(nil))
	want := config.Config{
		TypeSafeAPIKey:  "",
		TypeSafeBaseURL: "https://api.typesafe.ai",
		JevModel:        "jev-latest",
		OpenAIBaseURL:   "https://api.openai.com/v1",
		OpenAIAPIKey:    "",
		OpenAIModel:     "gpt-4o-mini",
	}
	if got != want {
		t.Errorf("Load(empty) = %+v, want %+v", got, want)
	}
}

func TestLoadOverridesEveryField(t *testing.T) {
	env := map[string]string{
		"TYPESAFE_API_KEY":         "ts-key-value",
		"TYPESAFE_BASE_URL":        "https://typesafe.internal.test",
		"INJECTIONBENCH_JEV_MODEL": "jev-custom",
		"OPENAI_BASE_URL":          "https://openai.internal.test",
		"OPENAI_API_KEY":           "oa-key-value",
		"OPENAI_MODEL":             "gpt-custom",
	}
	got := config.Load(lookupFrom(env))
	want := config.Config{ //nolint:gosec // G101: synthetic placeholder values asserting field wiring, not real credentials
		TypeSafeAPIKey:  "ts-key-value",
		TypeSafeBaseURL: "https://typesafe.internal.test",
		JevModel:        "jev-custom",
		OpenAIBaseURL:   "https://openai.internal.test",
		OpenAIAPIKey:    "oa-key-value",
		OpenAIModel:     "gpt-custom",
	}
	if got != want {
		t.Errorf("Load(overrides) = %+v, want %+v", got, want)
	}
}

func TestLoadEmptyValueFallsBackToDefault(t *testing.T) {
	env := map[string]string{
		"TYPESAFE_BASE_URL":        "",
		"INJECTIONBENCH_JEV_MODEL": "",
		"OPENAI_BASE_URL":          "",
		"OPENAI_MODEL":             "",
	}
	got := config.Load(lookupFrom(env))
	if got.TypeSafeBaseURL != "https://api.typesafe.ai" {
		t.Errorf("TypeSafeBaseURL = %q, want default", got.TypeSafeBaseURL)
	}
	if got.JevModel != "jev-latest" {
		t.Errorf("JevModel = %q, want default", got.JevModel)
	}
	if got.OpenAIBaseURL != "https://api.openai.com/v1" {
		t.Errorf("OpenAIBaseURL = %q, want default", got.OpenAIBaseURL)
	}
	if got.OpenAIModel != "gpt-4o-mini" {
		t.Errorf("OpenAIModel = %q, want default", got.OpenAIModel)
	}
}

func TestLoadPerFieldOverride(t *testing.T) {
	tests := []struct {
		name    string
		envKey  string
		value   string
		extract func(config.Config) string
	}{
		{"api key", "TYPESAFE_API_KEY", "v1", func(c config.Config) string { return c.TypeSafeAPIKey }},
		{"base url", "TYPESAFE_BASE_URL", "https://x.test", func(c config.Config) string { return c.TypeSafeBaseURL }},
		{"jev model", "INJECTIONBENCH_JEV_MODEL", "custom-jev", func(c config.Config) string { return c.JevModel }},
		{"openai base url", "OPENAI_BASE_URL", "https://y.test", func(c config.Config) string { return c.OpenAIBaseURL }},
		{"openai api key", "OPENAI_API_KEY", "v2", func(c config.Config) string { return c.OpenAIAPIKey }},
		{"openai model", "OPENAI_MODEL", "custom-model", func(c config.Config) string { return c.OpenAIModel }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.Load(lookupFrom(map[string]string{tt.envKey: tt.value}))
			if extracted := tt.extract(got); extracted != tt.value {
				t.Errorf("field for %s = %q, want %q", tt.envKey, extracted, tt.value)
			}
		})
	}
}

func TestFromEnvReadsProcessEnvironment(t *testing.T) {
	t.Setenv("OPENAI_MODEL", "from-process-env")
	t.Setenv("TYPESAFE_API_KEY", "")
	got := config.FromEnv()
	if got.OpenAIModel != "from-process-env" {
		t.Errorf("FromEnv().OpenAIModel = %q, want %q", got.OpenAIModel, "from-process-env")
	}
}
