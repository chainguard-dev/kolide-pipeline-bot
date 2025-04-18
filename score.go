package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genai"
	"k8s.io/klog/v2"
)

const (
	benign int = iota - 1
	undetermined
	suspicious
	malicious
)

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
		- If the "remote_address" is related to GitHub or Microsoft, it probably isn't as suspicious as it looks.

		Return a single-word verdict encapsulating whether the behavior and process tree contained within the JSON row is "benign", "undetermined", "suspicious", or "malicious", followed by a colon and a one to two sentence summary of the row.
		If you are uncertain, your verdict should always be "undetermined"; if VirusTotal results are not available, do not mention the lack of data.

		Your verdict and summary should never be empty; always provide a verdict and summary in the following format: "<verdict>: <summary>".

		Never:
		- Add backticks or quotation marks to the beginning or end of responses.
		- Include thoughts or reasoning in the summary.
		`,
		kind)

	// Use the smaller of the row content strings or maxBudget for the thinking budget
	tb := min(int32(len(strings.Fields(string(bs)))), maxBudget)
	klog.Infof("%s:%s - using thinking budget of %d", kind, device, tb)
	config := &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: []*genai.Part{{Text: prompt}},
		},
		// 1 is the default value, but this makes it easy to reference
		CandidateCount: 1,
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

	resp, err := ai.Models.GenerateContent(ctx, modelName, contents, config)
	if err != nil {
		return err
	}

	// Retry up to maxRetries in order to return a non-empty response
	for i := 0; len(resp.Candidates) == 0 && i < maxRetries; i++ {
		backoffDuration := time.Duration(math.Pow(2, float64(i))) * 500 * time.Millisecond
		time.Sleep(backoffDuration)

		klog.Infof("%s:%s - received empty candidate, retrying (%d/%d)", kind, device, i+1, maxRetries)

		next, err := ai.Models.GenerateContent(ctx, modelName, contents, config)
		if err != nil {
			klog.Infof("%s:%s - next GenerateContent request failed with error: %v", kind, device, err)
			continue
		}

		if len(next.Candidates) > 0 {
			resp = next
			break
		}
	}

	adjustment := undetermined
	for _, c := range resp.Candidates {
		var sb strings.Builder
		for _, ps := range c.Content.Parts {
			sb.WriteString(ps.Text)
		}
		p := sb.String()
		// The prompt should prevent responses wrapped or prefixed with backticks,
		// but trim them to be safe
		p = strings.TrimPrefix(p, "```")
		p = strings.TrimSuffix(p, "```")
		klog.Infof("%s:%s - vertex response: %s", kind, device, p)
		verdict, _, _ := strings.Cut(p, ": ")
		switch {
		case strings.Contains(strings.ToLower(verdict), "suspicious"):
			adjustment = suspicious
		case strings.Contains(strings.ToLower(verdict), "malicious"):
			adjustment = malicious
		case strings.Contains(strings.ToLower(verdict), "benign"):
			if containsUnknownBinary {
				klog.Infof("%s:%s - not adjusting benign result due to unknown binary", kind, device)
			} else {
				adjustment = benign
			}
		}
		row.Interpretation = p
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
