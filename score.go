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

	for _, v := range row.VirusTotal {
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
		This is the JSON output from Kolide, based on an osquery rule named %q that is part of osquery-defense-kit.

		The 'Row' struct is the content returned by the query. If an element starts with p0, it is the child process the alert is centered on. If an element starts with p1_, that is the parent of the process we alerted on. If the element begins with p2_, it is the grandparent process. The grandparent process launches the parent process, which launches the child process.
		The 'Decorations' struct contains information about the machine the query was run on.
		The 'VirusTotal' struct contains any additional information that VirusTotal discovered about the process or hosts returned by the query. If the VirusTotal struct is empty, it may mean that VirusTotal wasn't available.

		Return a single-word verdict of if the behavior and process tree described by this is benign, undetermined, suspicious, or malicious, followed by a colon and a 5-10 word summary of the row.
		`,
		kind))

	klog.Infof("%s:%s - vertex input: %s", kind, device, bs)
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
			adjustment = -1
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
