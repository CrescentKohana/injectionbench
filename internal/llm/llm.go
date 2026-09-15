// Package llm provides the Model interface InjectionBench's demo apps talk to, a seeded
// deterministic simulation of a naively instruction-following LLM, and an OpenAI-compatible
// chat-completions client.
package llm

import "context"

// Role identifies the speaker of a Message.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one turn of a chat-style conversation sent to a Model.
type Message struct {
	Role    Role
	Content string
}

// Tool describes a function the model may call; every parameter is a string.
type Tool struct {
	Name, Description string
	Parameters        []string
}

// ToolCall is a tool invocation the model chose to make.
type ToolCall struct {
	Name      string
	Arguments map[string]string
}

// Request is one completion request.
type Request struct {
	Messages []Message
	Tools    []Tool
}

// Completion is a model's response to a Request.
type Completion struct {
	Content   string
	ToolCalls []ToolCall
}

// Model generates a Completion for a Request.
type Model interface {
	Complete(ctx context.Context, req Request) (Completion, error)
}
