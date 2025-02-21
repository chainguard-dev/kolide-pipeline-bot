package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/vertexai/genai"
	"k8s.io/klog/v2"
)

func scoreRow(ctx context.Context, model *genai.GenerativeModel, row *DecoratedRow) error {
	// set a default score early in case we have to exit with an error
	row.Score = 1

	score := 1
	if strings.HasPrefix(row.Kind, "2") {
		score = 2
	}
	if strings.HasPrefix(row.Kind, "3") {
		score = 3
	}

	device := row.Decorations["computer_name"]
	klog.Infof("base score for %s (%s): %d", row.Kind, device, score)
	bs, err := json.MarshalIndent(row, "", "    ")
	if err != nil {
		return err
	}

	prompt := genai.Text(fmt.Sprintf(`
		This is the JSON output from Kolide, based on an osquery rule named %q that is part of osquery-defense-kit.

		The 'Row' struct is the content returned by the query. If an element starts with p0, it is the offending process. If it starts with p1_, it is the parent of that process. If it begins with p2_, it is the grandparent to that process.
		The 'Decorations' struct contains information about the machine the query was run on.
		The 'VirusTotal' struct contains any additional information that VirusTotal discovered about the process or hosts returned by the query. If it's empty, it may mean that this feature is disabled.

		Return a single-word verdict of if this output is most likely benign, suspicious, or malicious, followed by a colon and a 5-10 word summary of the row.
		`,
		row.Kind))

	resp, err := model.GenerateContent(ctx, genai.Text(string(bs)), prompt)
	if err != nil {
		return err
	}

	boost := 0
	for _, c := range resp.Candidates {
		p := c.Content.Parts[0]
		klog.Infof("response: %s", p)
		verdict, _, _ := strings.Cut(fmt.Sprintf("%s", p), ": ")
		switch {
		case strings.Contains(strings.ToLower(verdict), "suspicious"):
			boost = 1
		case strings.Contains(strings.ToLower(verdict), "malicious"):
			boost = 2
		}

		row.Interpretation = fmt.Sprintf("%s", p)
		if boost > 0 {
			klog.Infof("+%d score boost for %s (%s): %q", boost, row.Kind, device, p)
		}
		break
	}

	row.Score = score + boost
	klog.Infof("setting score %s (%s): %d [boost=%d]", row.Kind, device, score, boost)
	return nil
}
