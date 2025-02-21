package main

import (
	"context"
	"sort"

	"k8s.io/klog/v2"
)

// enqueueRow adds rows to the priority queue for later reference
func enqueueRow(ctx context.Context, pq map[string][]*DecoratedRow, row *DecoratedRow) {
	device := row.Decorations["computer_name"]

	for _, v := range row.VirusTotal {
		if v.Kind > Undetected {
			row.Score = row.Score + (int(v.Kind) - int(Undetected))
			klog.Infof("increasing score due to virustotal info")
		}
	}

	klog.Infof("enqueue[%s]: %s (score %d)", device, row.Kind, row.Score)
	pq[device] = append(pq[device], row)
}

// priorityDevices returns a list of devices that meet the minimum posting score
func priorityDevices(pq map[string][]*DecoratedRow, minScore int) []string {
	matches := []string{}

	for device, rows := range pq {
		if len(rows) == 0 {
			continue
		}
		klog.Infof("%s: analyzing %d row queue ...", device, len(rows))
		score := 0
		seen := map[string]bool{}
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].Score > rows[j].Score
		})

		for _, r := range rows {
			if !seen[r.Kind] {
				klog.Infof("haven't seen %s, setting score: %d [%s]", r.Kind, r.Score, r.Interpretation)
				score += r.Score
			}
			seen[r.Kind] = true
		}
		if score >= minScore {
			matches = append(matches, device)
		}
	}

	return matches
}
