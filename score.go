package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"cloud.google.com/go/vertexai/genai"
	"k8s.io/klog/v2"
)

func scoreRow(ctx context.Context, model *genai.GenerativeModel, row *DecoratedRow) error {
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

	prompt := genai.Text(fmt.Sprintf(`
		This is the JSON output from Kolide, based on an osquery rule named %q that is part of osquery-defense-kit. These JSON rows represent exceptions from the normal baseline in our environment.

		Almost all of the time these rows are just benign changes to our environment when people install new software, but we're also very cautious about subtle nation-state attackers getting a foothold in our environment.

		The 'Row' struct is the content returned by the query:
		- If an element starts with p0, it is the child process the alert is centered on.
		- If an element starts with p1_, that is the parent of the process we alerted on.
		- If the element begins with p2_, it is the grandparent process.
		- The grandparent process launches the parent process, which launches the child process.
		- If an element is named s_auth or authority, the binary is signed and approved by Apple. It could still be malware, particularly if it is signed by a rare application signer.
		- If an element is named s_id or identifier, that is the name of the binary that was signed and approved by Apple
		- Unsigned programs running longer than a day should be regarded with more suspicion than otherwise.

		The 'Decorations' struct contains information about the machine the query was run on. Think of it as a host information struct.

		The 'VirusTotal' struct contains additional information that VirusTotal discovered about the process or IP addresses
	    returned by the query.
		- If the VirusTotal struct is empty, it may mean that VirusTotal wasn't available.
		- A verdict of "undetected_no_opinion" means that VirusTotal did not know about this hash. This is much more common on Linux. It may be a program that the user built for themselves locally.
		- If a program is harmless_and_known, the tool itself probably benign, but even benign tools can be misused.
		- If the remote_address is related to GitHub or Microsoft, it probably isn't as suspicious as it looks.

		Return a single-word verdict of if the behavior and process tree described by this is benign, undetermined, suspicious, or malicious, followed by a colon and a 5-10 word summary of the row.

		If you are uncertain, your verdict should be undetermined.
		`,
		kind))

	resp, err := model.GenerateContent(ctx, genai.Text(string(bs)), prompt)
	if err != nil {
		return err
	}

	adjustment := 0
	for _, c := range resp.Candidates {
		p := c.Content.Parts[0]
		klog.Infof("%s:%s - vertex response: %s", kind, device, p)
		verdict, _, _ := strings.Cut(fmt.Sprintf("%s", p), ": ")
		switch {
		case strings.Contains(strings.ToLower(verdict), "suspicious"):
			adjustment = 1
		case strings.Contains(strings.ToLower(verdict), "malicious"):
			adjustment = 2
		case strings.Contains(strings.ToLower(verdict), "benign"):
			if containsUnknownBinary {
				klog.Infof("%s:%s - not adjusting benign result due to unknown binary", kind, device)
			} else {
				adjustment = -1
			}
		}

		row.Interpretation = fmt.Sprintf("%s", p)
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
