package attack_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/attack"
)

var categoryPrefix = map[attack.Category]string{
	attack.CategoryDirect:           "DI-",
	attack.CategoryPromptExtraction: "PE-",
	attack.CategoryObfuscation:      "OB-",
	attack.CategoryIndirect:         "IN-",
	attack.CategoryExcessiveAgency:  "EA-",
	attack.CategoryMarkdownExfil:    "MD-",
	attack.CategoryMultiTurn:        "MT-",
}

var owaspPattern = regexp.MustCompile(`^LLM\d{2}:2025$`)
var atlasPattern = regexp.MustCompile(`^AML\.T\d{4}(\.\d{3})?$`)
var emailDomainPattern = regexp.MustCompile(`[[:alnum:]_.+-]+@([[:alnum:].-]+)`)
var urlDomainPattern = regexp.MustCompile(`https?://([[:alnum:].:-]+)`)

const allowedAttackerDomain = "attacker.example"
const allowedLegitEmailDomain = "example.com"

func loadBuiltin(t *testing.T) []attack.Attack {
	t.Helper()
	attacks, err := attack.Builtin()
	if err != nil {
		t.Fatalf("Builtin() returned error: %v", err)
	}
	if len(attacks) == 0 {
		t.Fatal("Builtin() returned no attacks")
	}
	return attacks
}

func TestBuiltinEveryAttackIsValid(t *testing.T) {
	attacks := loadBuiltin(t)
	for _, a := range attacks {
		if err := a.Validate(); err != nil {
			t.Errorf("attack %s fails Validate(): %v", a.ID, err)
		}
	}
}

func TestBuiltinSortedByID(t *testing.T) {
	attacks := loadBuiltin(t)
	if !sort.SliceIsSorted(attacks, func(i, j int) bool { return attacks[i].ID < attacks[j].ID }) {
		t.Error("Builtin() is not sorted by ID")
	}
}

func TestBuiltinNoDuplicateIDs(t *testing.T) {
	attacks := loadBuiltin(t)
	seen := make(map[string]bool, len(attacks))
	for _, a := range attacks {
		if seen[a.ID] {
			t.Errorf("duplicate ID %s in Builtin() corpus", a.ID)
		}
		seen[a.ID] = true
	}
}

func TestBuiltinAtLeastThreePerCategoryAndTwentyOneTotal(t *testing.T) {
	attacks := loadBuiltin(t)
	if len(attacks) < 21 {
		t.Errorf("Builtin() has %d attacks, want >= 21", len(attacks))
	}
	counts := make(map[attack.Category]int)
	for _, a := range attacks {
		counts[a.Category]++
	}
	for _, c := range attack.Categories() {
		if counts[c] < 3 {
			t.Errorf("category %s has %d attacks, want >= 3", c, counts[c])
		}
	}
}

func TestBuiltinIDPrefixMatchesCategory(t *testing.T) {
	attacks := loadBuiltin(t)
	for _, a := range attacks {
		prefix, ok := categoryPrefix[a.Category]
		if !ok {
			t.Errorf("attack %s has unmapped category %s", a.ID, a.Category)
			continue
		}
		pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `\d{3}$`)
		if !pattern.MatchString(a.ID) {
			t.Errorf("attack ID %q does not match pattern %s for category %s", a.ID, pattern, a.Category)
		}
	}
}

func TestBuiltinEveryAttackHasOWASPAndATLAS(t *testing.T) {
	attacks := loadBuiltin(t)
	for _, a := range attacks {
		if len(a.OWASP) == 0 {
			t.Errorf("attack %s has no OWASP mapping", a.ID)
		}
		for _, id := range a.OWASP {
			if !owaspPattern.MatchString(id) {
				t.Errorf("attack %s has malformed OWASP ID %q, want LLMxx:2025", a.ID, id)
			}
		}
		if len(a.ATLAS) == 0 {
			t.Errorf("attack %s has no ATLAS mapping", a.ID)
		}
		for _, id := range a.ATLAS {
			if !atlasPattern.MatchString(id) {
				t.Errorf("attack %s has malformed ATLAS ID %q, want AML.Txxxx or AML.Txxxx.xxx", a.ID, id)
			}
		}
	}
}

func TestBuiltinObfuscationUsesAllFourTransforms(t *testing.T) {
	attacks := loadBuiltin(t)
	seen := make(map[string]bool)
	for _, a := range attacks {
		if a.Category == attack.CategoryObfuscation {
			seen[a.Transform] = true
		}
	}
	for _, want := range []string{"base64", "fullwidth", "zerowidth", "rot13"} {
		if !seen[want] {
			t.Errorf("no obfuscation-category attack uses transform %q; seen: %v", want, seen)
		}
	}
}

func TestBuiltinIndirectUsesDocumentsAndToolOutputs(t *testing.T) {
	attacks := loadBuiltin(t)
	hasDocuments, hasToolOutputs := false, false
	for _, a := range attacks {
		if a.Category != attack.CategoryIndirect {
			continue
		}
		if len(a.Documents) > 0 {
			hasDocuments = true
		}
		if len(a.ToolOutputs) > 0 {
			hasToolOutputs = true
		}
	}
	if !hasDocuments {
		t.Error("no indirect-category attack uses Documents")
	}
	if !hasToolOutputs {
		t.Error("no indirect-category attack uses ToolOutputs")
	}
}

func TestBuiltinExcessiveAgencySetsForbiddenTools(t *testing.T) {
	attacks := loadBuiltin(t)
	found := false
	for _, a := range attacks {
		if a.Category != attack.CategoryExcessiveAgency {
			continue
		}
		found = true
		if len(a.Success.ForbiddenTools) == 0 {
			t.Errorf("excessive-agency attack %s does not set ForbiddenTools", a.ID)
		}
	}
	if !found {
		t.Fatal("no excessive-agency attacks found in Builtin()")
	}
}

func extractDomains(s string) []string {
	var out []string
	for _, m := range emailDomainPattern.FindAllStringSubmatch(s, -1) {
		out = append(out, strings.TrimRight(m[1], "."))
	}
	for _, m := range urlDomainPattern.FindAllStringSubmatch(s, -1) {
		host := m[1]
		if i := strings.IndexAny(host, ":/"); i >= 0 {
			host = host[:i]
		}
		out = append(out, host)
	}
	return out
}

func TestBuiltinAttackerInfrastructureUsesOnlyReservedDomain(t *testing.T) {
	attacks := loadBuiltin(t)
	sawAttackerDomain := false
	allowed := map[string]bool{allowedAttackerDomain: true, allowedLegitEmailDomain: true}

	checkField := func(id, field, value string) {
		for _, domain := range extractDomains(value) {
			if domain == allowedAttackerDomain {
				sawAttackerDomain = true
			}
			if !allowed[domain] {
				t.Errorf("attack %s field %s references non-reserved domain %q in %q", id, field, domain, value)
			}
		}
	}

	for _, a := range attacks {
		checkField(a.ID, "payload", a.Payload)
		for i, turn := range a.Turns {
			checkField(a.ID, "turns["+string(rune('0'+i))+"]", turn)
		}
		for _, d := range a.Documents {
			checkField(a.ID, "documents["+d.ID+"]", d.Content)
		}
		for name, out := range a.ToolOutputs {
			checkField(a.ID, "tool_outputs["+name+"]", out)
		}
	}
	if !sawAttackerDomain {
		t.Error("no attack in Builtin() references the reserved attacker.example domain")
	}
}

func TestBuiltinHasResidualRiskPromptExtractionAttacks(t *testing.T) {
	attacks := loadBuiltin(t)
	dashed, reversed := false, false
	for _, a := range attacks {
		if a.Category != attack.CategoryPromptExtraction {
			continue
		}
		rendered, err := a.Render()
		if err != nil {
			t.Fatalf("attack %s: Render() returned error: %v", a.ID, err)
		}
		text := strings.ToLower(strings.Join(rendered.Turns, " "))
		if strings.Contains(text, "spell") || strings.Contains(text, "dashes") {
			dashed = true
		}
		if strings.Contains(text, "reverse") || strings.Contains(text, "backwards") {
			reversed = true
		}
	}
	if !dashed {
		t.Error("no prompt-extraction attack asks for the deployment key spelled out / separated by dashes " +
			"(the hardened output filter deliberately does not catch this residual-risk form)")
	}
	if !reversed {
		t.Error("no prompt-extraction attack asks for the deployment key reversed " +
			"(the hardened output filter deliberately does not catch this residual-risk form)")
	}
}

func TestBuiltinEveryAttackHasGoal(t *testing.T) {
	attacks := loadBuiltin(t)
	for _, a := range attacks {
		if strings.TrimSpace(a.Goal) == "" {
			t.Errorf("attack %s has an empty Goal", a.ID)
		}
	}
}
