package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/genai"
	"k8s.io/klog/v2"
)

const (
	benign int = iota - 1
	undetermined
	suspicious
	malicious
)

type aiResponse struct {
	Verdict        string `json:"verdict"`
	Summary        string `json:"summary"`
	ThoughtProcess string `json:"thought_process"`
}

func scoreRow(ctx context.Context, ai *genai.Client, row *DecoratedRow) error {
	kind := row.Kind
	prefix, after, _ := strings.Cut(kind, "_")
	score := int(0)

	i, err := strconv.ParseInt(prefix, 10, 0)
	if err != nil {
		klog.Errorf("unable to get score from prefix %q: %v", prefix, err)
	} else {
		score = int(i)
		kind = after
	}

	// set a default score early in case we have to exit with an error
	device := row.Decorations["computer_name"]
	klog.Infof("%s:%s - base score: %d", row.Kind, device, score)
	row.Score = score
	containsUnknownBinary := false

	for k, v := range row.VirusTotal {
		if (strings.Contains(k, "sha256") || strings.HasSuffix(k, "_hash")) && v.Score == MissingUnknown {
			containsUnknownBinary = true
		}
		if v.Score > NoOpinion {
			modifier := (int(v.Score) - int(NoOpinion))
			klog.Infof("%s:%s - adding +%d to score due to VirusTotal: %+v", device, kind, modifier, v)
			row.Score = row.Score + modifier
		}
	}

	bs, err := json.MarshalIndent(row, "", "    ")
	if err != nil {
		return err
	}

	prompt := fmt.Sprintf(`
		The following content is the JSON output from Kolide based on an osquery rule named %q which is part of osquery-defense-kit.

		The JSON content is a row which represents a deviation from the routine, established baseline in our environment.

		Most of the time, these query results are harmless fluctuations within our environment such as new software being installed or executed; however, we are also extremely cautious about and sensitive to subtle nation-state attackers (APTs) gaining a foothold in our environment.

		Your responsibility is to parse the JSON content keeping the following context in mind:
		1. The 'Row' struct contains the content returned by the osquery query:
		- If an element begins with "p0_", it is the child process in the query result.
		- If an element begins with "p1_", it is the parent of the child process in the query result.
		- If an element begins with "p2_", it is the grandparent of the child process in the query result.
		- The grandparent process launches the parent process, which, in turn, launches the child process.
		- If an element is named "s_auth" or "authority", the binary is signed and approved by Apple. The binary could still be malicious, particularly if it is signed by a rare or unexpected/unknown application signer.
		- If an element is named "s_id" or "identifier", it is the name of the binary that was signed and approved by Apple.
		- Unsigned programs running longer than a day should be regarded with more suspicion.

		2. The 'Decorations' struct contains information about the machine the query was run on. Think of it as a host information struct.

		3. The 'VirusTotal' struct contains additional information that VirusTotal discovered about the process or IP addresses returned by the osquery query:
		- If the VirusTotal struct is empty, it may mean that VirusTotal wasn't available (API error, rate limit, outage, etc.).
		- A verdict of "undetected_no_opinion" means that VirusTotal did not know about the specified hash. This is much more common on Linux. It may be a binary that the user built themselves locally.
		- If a program is "harmless_and_known", the tool itself probably benign, but even benign tools can be misused.
		- If the "remote_address" is related to GitHub, Google, or Microsoft, it probably isn't as suspicious as it looks.

		Your response should be a raw valid parseable JSON object with the following attributes:

		- verdict:  a single-word verdict encapsulating whether the behavior and process tree contained within the JSON row is "benign", "undetermined", "suspicious", or "malicious". If you are uncertain, the verdict should be "undetermined"
		- summary: terse summary of the event observed and why you arrived at your verdict. preferably 1 sentence, but no more than 2.
		- thought_process: how you thought about this

		VirusTotal will often not have matches for sha256 checksums in our environment, so it is not necessary to note the lack of them in your summary.
		`,
		kind)

	// Use the smaller of the row content strings or maxBudget for the thinking budget
	tb := min(int32(len(strings.Fields(string(bs)))), maxBudget)
	temp := float32(0)
	seed := int32(0)
	klog.Infof("%s:%s - using thinking budget of %d", kind, device, tb)
	config := &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: []*genai.Part{{Text: prompt}},
		},
		// 1 is the default value, but this makes it easy to reference
		CandidateCount:   1,
		ResponseMIMEType: "application/json",
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: false,
			ThinkingBudget:  &tb,
		},
		// Tweak the response to allow references to content like malware, viruses, and other malicious behavior
		SafetySettings: []*genai.SafetySetting{
			{Category: "HARM_CATEGORY_DANGEROUS_CONTENT"},
			{Threshold: "OFF"},
		},
	}
	contents := []*genai.Content{
		{
			Parts: []*genai.Part{{Text: string(bs)}},
			Role:  "model",
		},
	}

	gcr, err := ai.Models.GenerateContent(ctx, modelName, contents, config)
	if err != nil {
		return err
	}

	adjustment := undetermined
	for _, c := range gcr.Candidates {
		var sb strings.Builder
		for _, ps := range c.Content.Parts {
			klog.Infof("candidate text:\n%s", ps.Text)
			for _, ln := range strings.Split(ps.Text, "\n") {
				// remove stray markdown
				if !strings.HasPrefix(ln, "```") {
					sb.WriteString(ln)
				}
			}
		}

		var resp aiResponse
		data := []byte(sb.String())
		err := json.Unmarshal([]byte(sb.String()), &resp)
		if err != nil {
			return fmt.Errorf("unmarshal[%s]: %w", data, err)
		}
		klog.Infof("%s:%s - vertex response: %s: %s", kind, device, resp.Verdict, resp.Summary)

		switch resp.Verdict {
		case "suspicious":
			adjustment = suspicious
		case "malicious":
			adjustment = malicious
		case "benign":
			if containsUnknownBinary {
				klog.Infof("%s:%s - not adjusting benign result due to unknown binary", kind, device)
			} else {
				adjustment = benign
			}
		}
		row.Interpretation = fmt.Sprintf("%s: %s", resp.Verdict, resp.Summary)
		if adjustment != 0 {
			klog.Infof("%s:%s - vertex score adjustment: %d", kind, device, adjustment)
		}
		break
	}

	row.Score = score + adjustment
	row.Kind = kind
	klog.Infof("%s:%s - final score: %d", kind, device, row.Score)
	return nil
}
