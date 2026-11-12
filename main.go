package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type cliOutput struct {
	OK     bool    `json:"ok"`
	Check  string  `json:"check,omitempty"`
	Reason *string `json:"reason"`
	Anchor string  `json:"anchor"`
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			printInternal(fmt.Sprintf("%v", r))
		}
	}()

	if len(os.Args) != 2 {
		printNoArg()
		return
	}

	res := verifyMoltPackage(os.Args[1])

	out := cliOutput{
		OK:     res.Valid,
		Anchor: "none",
	}

	if res.Anchor == "verified" {
		out.Anchor = "present"
	}

	if !res.Valid {
		out.Check = res.CheckID
		reason := res.Reason
		out.Reason = &reason
	}

	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

func printInternal(msg string) {
	out := map[string]any{
		"ok":     false,
		"reason": "adapter: threw: " + msg,
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}

func printNoArg() {
	out := map[string]any{
		"ok":     false,
		"reason": "adapter: no package dir",
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
