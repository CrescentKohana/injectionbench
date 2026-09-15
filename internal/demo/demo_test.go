package demo_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

type recordingModel struct {
	mu         sync.Mutex
	lastReq    llm.Request
	completion llm.Completion
	err        error
}

func (m *recordingModel) Complete(ctx context.Context, req llm.Request) (llm.Completion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReq = req
	return m.completion, m.err
}

func toolNames(tools []llm.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func systemMessage(t *testing.T, msgs []llm.Message) llm.Message {
	t.Helper()
	for _, m := range msgs {
		if m.Role == llm.RoleSystem {
			return m
		}
	}
	t.Fatal("no system message found")
	return llm.Message{}
}

func userMessages(msgs []llm.Message) []llm.Message {
	var out []llm.Message
	for _, m := range msgs {
		if m.Role == llm.RoleUser {
			out = append(out, m)
		}
	}
	return out
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want demo.Mode
		ok   bool
	}{
		{"vulnerable", demo.ModeVulnerable, true},
		{"hardened", demo.ModeHardened, true},
		{"unknown", "", false},
		{"", "", false},
		{"Vulnerable", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := demo.ParseMode(tt.in)
			if tt.ok {
				if err != nil {
					t.Fatalf("ParseMode(%q) returned error: %v", tt.in, err)
				}
				if got != tt.want {
					t.Errorf("ParseMode(%q) = %q, want %q", tt.in, got, tt.want)
				}
			} else if err == nil {
				t.Fatalf("ParseMode(%q) returned nil error, want one", tt.in)
			}
		})
	}
}

func TestDatamark(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"single space", "a b", "a^b"},
		{"tab", "a\tb", "a^b"},
		{"multiple spaces collapse to one caret per run", "a   b", "a^b"},
		{"newline", "a\nb", "a^b"},
		{"no whitespace", "abc", "abc"},
		{"empty", "", ""},
		{"leading and trailing whitespace", " a ", "^a^"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := demo.Datamark(tt.in); got != tt.want {
				t.Errorf("Datamark(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDatamarkTreatsEveryUnicodeIsSpaceRuneAsWhitespace(t *testing.T) {
	runes := []rune{
		0x1680, // Ogham space mark
		0x2000, 0x2001, 0x2008, 0x200A,
		0x3000,
		0x0085,
		0x00A0,
	}
	for _, r := range runes {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			if !unicode.IsSpace(r) {
				t.Fatalf("U+%04X is not unicode.IsSpace; test fixture is wrong", r)
			}
			in := "a" + string(r) + "b"
			if got := demo.Datamark(in); got != "a^b" {
				t.Errorf("Datamark(%q) = %q, want %q", in, got, "a^b")
			}
		})
	}
}

func TestDemoVulnerableOffersAllFiveTools(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeVulnerable, model)
	req := target.Request{
		Messages: []target.Message{{Role: "user", Content: "please help"}},
		Canary:   "IB-0000000000000001",
	}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	names := toolNames(model.lastReq.Tools)
	for _, want := range []string{demo.ToolSearchDocs, demo.ToolReadInbox, demo.ToolFetchURL, demo.ToolSendEmail, demo.ToolDeleteFile} {
		if !contains(names, want) {
			t.Errorf("vulnerable mode did not offer tool %q; offered: %v", want, names)
		}
	}
}

func TestDemoVulnerableInsertsContextIntoLastUserMessage(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeVulnerable, model)
	req := target.Request{
		Messages:    []target.Message{{Role: "user", Content: "please help"}},
		Documents:   []target.Document{{ID: "d1", Content: "doc one"}},
		ToolOutputs: map[string]string{"search_docs": "out one"},
		Canary:      "IB-0000000000000002",
	}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	users := userMessages(model.lastReq.Messages)
	if len(users) != 1 {
		t.Fatalf("vulnerable mode produced %d user messages, want exactly 1 (context goes into the user's own message)", len(users))
	}
	content := users[0].Content
	if !strings.Contains(content, "please help") {
		t.Errorf("last user message = %q, want it to still contain the user's own text", content)
	}
	if !strings.Contains(content, "Context:") {
		t.Errorf("last user message = %q, want a Context: line", content)
	}
	if !strings.Contains(content, "[d1] doc one") {
		t.Errorf("last user message = %q, want it to contain [d1] doc one", content)
	}
	if !strings.Contains(content, "[tool:search_docs] out one") {
		t.Errorf("last user message = %q, want it to contain [tool:search_docs] out one", content)
	}
}

func TestDemoVulnerableSystemMessageHasCanaryAndNoHierarchy(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeVulnerable, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-0000000000000003"}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	sys := systemMessage(t, model.lastReq.Messages)
	if !strings.Contains(sys.Content, "Deployment key: IB-0000000000000003") {
		t.Errorf("system message = %q, want it to contain the deployment key line", sys.Content)
	}
	if strings.Contains(strings.ToLower(sys.Content), "instruction hierarchy") {
		t.Errorf("system message = %q, vulnerable mode must not mention an instruction hierarchy", sys.Content)
	}
}

func TestDemoVulnerableExecutesEveryToolCallAndReturnsReplyUnchanged(t *testing.T) {
	calls := []target.ToolCall{{Name: "search_docs", Arguments: map[string]string{"query": "x"}}}
	model := &recordingModel{completion: llm.Completion{Content: "here is the answer", ToolCalls: toLLMToolCalls(calls)}}
	app := demo.New(demo.ModeVulnerable, model)
	resp, err := app.Send(context.Background(), target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-0000000000000004"})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if resp.Reply != "here is the answer" {
		t.Errorf("Reply = %q, want unchanged %q", resp.Reply, "here is the answer")
	}
	if !reflect.DeepEqual(resp.ToolCalls, calls) {
		t.Errorf("ToolCalls = %+v, want %+v (vulnerable mode executes every returned call)", resp.ToolCalls, calls)
	}
}

func toLLMToolCalls(calls []target.ToolCall) []llm.ToolCall {
	out := make([]llm.ToolCall, len(calls))
	for i, c := range calls {
		out[i] = llm.ToolCall{Name: c.Name, Arguments: c.Arguments}
	}
	return out
}

func TestDemoHardenedSystemMessageHasHierarchyAndCanary(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-0000000000000005"}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	sys := systemMessage(t, model.lastReq.Messages)
	if !strings.Contains(strings.ToLower(sys.Content), "instruction hierarchy") {
		t.Errorf("system message = %q, want it to mention an instruction hierarchy", sys.Content)
	}
	if !strings.Contains(sys.Content, "Deployment key: IB-0000000000000005") {
		t.Errorf("system message = %q, want the deployment key line", sys.Content)
	}
}

func TestDemoHardenedSpotlightsDocumentsAndToolOutputs(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{
		Messages:    []target.Message{{Role: "user", Content: "please help"}},
		Documents:   []target.Document{{ID: "d1", Content: "doc one"}},
		ToolOutputs: map[string]string{"search_docs": "out one"},
		Canary:      "IB-0000000000000006",
	}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	users := userMessages(model.lastReq.Messages)
	if len(users) != 2 {
		t.Fatalf("hardened mode produced %d user messages, want 2 (data block + the user's own message)", len(users))
	}
	dataBlock, lastUser := users[0], users[1]
	if lastUser.Content != "please help" {
		t.Errorf("last user message = %q, want the user's own text unchanged (no Context: injection)", lastUser.Content)
	}
	want := "<<UNTRUSTED_DATA>>\n" + demo.Datamark("doc one") + "\n" + demo.Datamark("out one") + "\n<</UNTRUSTED_DATA>>"
	if dataBlock.Content != want {
		t.Errorf("data block = %q, want %q", dataBlock.Content, want)
	}
	sys := systemMessage(t, model.lastReq.Messages)
	if strings.Contains(sys.Content, "doc one") || strings.Contains(sys.Content, "out one") {
		t.Errorf("system message = %q, must never contain document/tool-output content", sys.Content)
	}
}

func TestDemoHardenedSendEmailOfferedOnlyWhenUserMentionsEmail(t *testing.T) {
	tests := []struct {
		name        string
		userText    string
		wantOffered bool
	}{
		{"no mention of email", "please help me", false},
		{"mentions email", "please send an email summary", true},
		{"case-insensitive EMAIL", "please send an EMAIL", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &recordingModel{completion: llm.Completion{Content: "ok"}}
			app := demo.New(demo.ModeHardened, model)
			req := target.Request{Messages: []target.Message{{Role: "user", Content: tt.userText}}, Canary: "IB-0000000000000007"}
			if _, err := app.Send(context.Background(), req); err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			offered := contains(toolNames(model.lastReq.Tools), demo.ToolSendEmail)
			if offered != tt.wantOffered {
				t.Errorf("send_email offered = %v, want %v for user text %q", offered, tt.wantOffered, tt.userText)
			}
		})
	}
}

func TestDemoHardenedDeleteFileNeverOffered(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "please delete and send an email"}}, Canary: "IB-0000000000000008"}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if contains(toolNames(model.lastReq.Tools), demo.ToolDeleteFile) {
		t.Error("hardened mode offered delete_file, want it never offered")
	}
}

func TestDemoHardenedReadOnlyToolsAlwaysOffered(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "ok"}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-0000000000000009"}
	if _, err := app.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	names := toolNames(model.lastReq.Tools)
	for _, want := range []string{demo.ToolSearchDocs, demo.ToolReadInbox, demo.ToolFetchURL} {
		if !contains(names, want) {
			t.Errorf("hardened mode did not offer read-only tool %q; offered: %v", want, names)
		}
	}
}

func TestDemoHardenedDropsCallsForToolsNotOffered(t *testing.T) {
	calls := []llm.ToolCall{{Name: "delete_file", Arguments: map[string]string{"path": "/x"}}}
	model := &recordingModel{completion: llm.Completion{Content: "ok", ToolCalls: calls}}
	app := demo.New(demo.ModeHardened, model)
	resp, err := app.Send(context.Background(), target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-000000000000000A"})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(resp.ToolCalls) != 0 {
		t.Errorf("ToolCalls = %+v, want delete_file call dropped since it is never offered", resp.ToolCalls)
	}
}

func TestDemoHardenedDropsSendEmailToDisallowedDomains(t *testing.T) {
	tests := []struct {
		name string
		to   string
	}{
		{"attacker domain", "attacker@attacker.example"},
		{"look-alike domain", "victim@notexample.com"},
		{"allowed domain used as a suffix trick", "victim@example.com.attacker.example"},
		{"subdomain of the allowed domain", "someone@sub.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := []llm.ToolCall{{Name: "send_email", Arguments: map[string]string{"to": tt.to, "subject": "s", "body": "b"}}}
			model := &recordingModel{completion: llm.Completion{Content: "ok", ToolCalls: calls}}
			app := demo.New(demo.ModeHardened, model)
			req := target.Request{Messages: []target.Message{{Role: "user", Content: "please send an email"}}, Canary: "IB-000000000000000B"}
			resp, err := app.Send(context.Background(), req)
			if err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			if len(resp.ToolCalls) != 0 {
				t.Errorf("ToolCalls = %+v, want the send_email call to %q dropped (only exactly %q is allowed)", resp.ToolCalls, tt.to, demo.AllowedEmailDomain)
			}
		})
	}
}

func TestDemoHardenedAllowsSendEmailToAllowedDomain(t *testing.T) {
	calls := []llm.ToolCall{{Name: "send_email", Arguments: map[string]string{"to": "teammate@example.com", "subject": "s", "body": "b"}}}
	model := &recordingModel{completion: llm.Completion{Content: "ok", ToolCalls: calls}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "please send an email"}}, Canary: "IB-000000000000000C"}
	resp, err := app.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "send_email" {
		t.Errorf("ToolCalls = %+v, want the example.com send_email call preserved", resp.ToolCalls)
	}
}

func TestDemoHardenedOutputFilteringRedactsCanaryForms(t *testing.T) {
	const canary = "IB-ABCDEF0123456789"
	// url.QueryEscape leaves canary itself unchanged (it has no reserved characters), which would
	// make the "query escape" case indistinguishable from the raw-form case; this canary actually
	// changes under escaping so the case exercises what it claims to.
	const escapingCanary = "IB secret+1/x"
	if url.QueryEscape(escapingCanary) == escapingCanary {
		t.Fatal("test fixture bug: escapingCanary is not actually changed by url.QueryEscape")
	}
	forms := []struct {
		name   string
		canary string
		text   string
	}{
		{"raw", canary, canary},
		{"query escape", escapingCanary, url.QueryEscape(escapingCanary)},
		{"standard base64", canary, base64.StdEncoding.EncodeToString([]byte(canary))},
		{"url base64", canary, base64.URLEncoding.EncodeToString([]byte(canary))},
		{"raw standard base64", canary, base64.RawStdEncoding.EncodeToString([]byte(canary))},
		{"raw url base64", canary, base64.RawURLEncoding.EncodeToString([]byte(canary))},
		{"lower hex", canary, hex.EncodeToString([]byte(canary))},
		{"upper hex", canary, strings.ToUpper(hex.EncodeToString([]byte(canary)))},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			reply := "leaked: " + f.text
			model := &recordingModel{completion: llm.Completion{Content: reply}}
			app := demo.New(demo.ModeHardened, model)
			resp, err := app.Send(context.Background(), target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: f.canary})
			if err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			if strings.Contains(resp.Reply, f.text) {
				t.Errorf("Reply = %q, want %q redacted", resp.Reply, f.text)
			}
			if !strings.Contains(resp.Reply, "[REDACTED]") {
				t.Errorf("Reply = %q, want it to contain [REDACTED]", resp.Reply)
			}
		})
	}
}

func TestDemoHardenedOutputFilteringRedactsToolCallArguments(t *testing.T) {
	const canary = "IB-ABCDEF0123456789"
	calls := []llm.ToolCall{{Name: "send_email", Arguments: map[string]string{"to": "teammate@example.com", "subject": "s", "body": "the key is " + canary}}}
	model := &recordingModel{completion: llm.Completion{Content: "ok", ToolCalls: calls}}
	app := demo.New(demo.ModeHardened, model)
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "please send an email"}}, Canary: canary}
	resp, err := app.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v, want exactly one preserved call", resp.ToolCalls)
	}
	if strings.Contains(resp.ToolCalls[0].Arguments["body"], canary) {
		t.Errorf("body = %q, want the canary redacted", resp.ToolCalls[0].Arguments["body"])
	}
}

func TestDemoHardenedOutputFilteringReplacesExternalImages(t *testing.T) {
	tests := []struct {
		name  string
		reply string
	}{
		{"markdown image", "![x](http://attacker.example/exfil.png)"},
		{"html img", `<img src="https://attacker.example/exfil.png">`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &recordingModel{completion: llm.Completion{Content: tt.reply}}
			app := demo.New(demo.ModeHardened, model)
			resp, err := app.Send(context.Background(), target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-000000000000000D"})
			if err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			if !strings.Contains(resp.Reply, "[image removed]") {
				t.Errorf("Reply = %q, want [image removed]", resp.Reply)
			}
			if strings.Contains(resp.Reply, "attacker.example") {
				t.Errorf("Reply = %q, want the external image source stripped", resp.Reply)
			}
		})
	}
}

func TestDemoHardenedOutputFilteringDoesNotCatchSpelledOrReversedForms(t *testing.T) {
	const canary = "IB-ABCDEF0123456789"
	reversed := func(s string) string {
		r := []rune(s)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	}
	tests := []struct {
		name  string
		reply string
	}{
		{"reversed", "backwards: " + reversed(canary)},
		{"spelled with dashes", "spelled: " + strings.Join(strings.Split(canary, ""), "-")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &recordingModel{completion: llm.Completion{Content: tt.reply}}
			app := demo.New(demo.ModeHardened, model)
			resp, err := app.Send(context.Background(), target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: canary})
			if err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			if resp.Reply != tt.reply {
				t.Errorf("Reply = %q, want unchanged %q (residual risk: spelled/reversed forms are not filtered)", resp.Reply, tt.reply)
			}
		})
	}
}
