package demo

import "github.com/CrescentKohana/injectionbench/internal/llm"

func searchDocsTool() llm.Tool {
	return llm.Tool{Name: ToolSearchDocs, Description: "Searches internal documentation.", Parameters: []string{"query"}}
}

func readInboxTool() llm.Tool {
	return llm.Tool{Name: ToolReadInbox, Description: "Reads the user's inbox."}
}

func fetchURLTool() llm.Tool {
	return llm.Tool{Name: ToolFetchURL, Description: "Fetches the contents of a URL.", Parameters: []string{"url"}}
}

func sendEmailTool() llm.Tool {
	return llm.Tool{Name: ToolSendEmail, Description: "Sends an email.", Parameters: []string{"to", "subject", "body"}}
}

func deleteFileTool() llm.Tool {
	return llm.Tool{Name: ToolDeleteFile, Description: "Deletes a file.", Parameters: []string{"path"}}
}

func allTools() []llm.Tool {
	return []llm.Tool{searchDocsTool(), readInboxTool(), fetchURLTool(), sendEmailTool(), deleteFileTool()}
}

func toolNameSet(tools []llm.Tool) map[string]bool {
	set := make(map[string]bool, len(tools))
	for _, t := range tools {
		set[t.Name] = true
	}
	return set
}
