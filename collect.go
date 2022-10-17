package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/VirusTotal/vt-go"
	"google.golang.org/api/iterator"
	"k8s.io/klog/v2"
)

type OutFile struct {
	DiffResults       diffResults       `json:"diffResults"`
	Name              string            `json:"name"`
	Decorations       map[string]string `json:"decorations"`
	KolideDecorations KolideDecorations `json:"kolide_decorations"`
	UNIXTime          int64             `json:"unixTime"`
}

type KolideDecorations struct {
	DeviceOwnerEmail  string `json:"device_owner_email"`
	DeviceDisplayName string `json:"device_display_name"`
	DeviceOwnerType   string `json:"device_owner_type"`
}

type diffResults struct {
	Removed []Row
	Added   []Row
}

type Row map[string]string

type DecoratedRow struct {
	Decorations map[string]string
	Kind        string
	UNIXTime    int64
	Row         Row
	VirusTotal  VTRow
}

func (r Row) String() string {
	var sb strings.Builder
	var kb strings.Builder

	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sinceBreak := 0

	for _, k := range keys {
		v := r[k]

		// exception keys are printed last
		if strings.HasSuffix(k, "exception") || strings.HasSuffix(k, "_key") {
			if kb.Len() == 0 {
				kb.WriteString("\n\n")
			}
			kb.WriteString(fmt.Sprintf("> %s: '%s'\n", k, v))
			continue
		}

		if len(v) > 384 {
			v = v[0:384] + "..."
		}
		text := fmt.Sprintf(`%s:%s `, k, v)
		if strings.Contains(v, " ") || strings.Contains(v, ":") {
			text = fmt.Sprintf(`%s:'%s' `, k, v)
		}

		if sinceBreak > 100 || (sinceBreak > 0 && (len(text)+sinceBreak) > 100) {
			sb.WriteString("\n> ")
			sinceBreak = len(text)
		} else {
			sinceBreak += len(text)
		}

		sb.WriteString(text)
	}

	return strings.TrimSpace(sb.String() + kb.String())
}

type CollectConfig struct {
	Prefix         string
	Cutoff         time.Time
	ExcludeSubdirs []string
}

func getRows(ctx context.Context, bucket *storage.BucketHandle, vtc *vt.Client, cc *CollectConfig) []DecoratedRow {
	klog.Infof("finding items matching: %+v ...", cc)
	it := bucket.Objects(ctx, &storage.Query{Prefix: cc.Prefix})
	lastKind := ""

	rows := []DecoratedRow{}
	seen := map[string]bool{}

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			klog.Errorf("error fetching objects: %v", err)
			break
		}

		matched := false
		for _, d := range cc.ExcludeSubdirs {
			if strings.Contains(attrs.Name, "/"+d+"/") {
				matched = true
				break
			}
		}

		if matched || attrs.Created.Before(cc.Cutoff) {
			continue
		}

		klog.Infof("reading %s ...", attrs.Name)
		rc, err := bucket.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			klog.Fatal(err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			klog.Fatal(err)
		}

		// Inconsistency warning: we've seen records returned as an array and as a struct
		out := OutFile{}
		err = json.Unmarshal(body, &out)

		// Try again by decoding it as an array
		if err != nil {
			outArr := []OutFile{}
			errArr := json.Unmarshal(body, &outArr)
			if errArr != nil {
				klog.Errorf("unmarshal(%s): %v\nsecond attempt: %v", body, err, errArr)
				continue
			}
			out = outArr[0]
		}

		kind := filepath.Base(filepath.Dir(filepath.Dir(attrs.Name)))
		if kind != lastKind {
			klog.Infof("=== kind: %s ===", kind)
			lastKind = kind
		}

		for _, r := range out.DiffResults.Added {
			msg := fmt.Sprintf("%s/%s (%+v): %s", kind, out.Decorations["computer_name"], out.KolideDecorations, r)
			if !seen[msg] {
				klog.Infof("collecting: %s", msg)
				vt, err := vtMetadata(r, vtc)
				if err != nil {
					klog.Errorf("failed to fetch VT metadata: %v", err)
				}
				row := DecoratedRow{
					Decorations: out.Decorations,
					UNIXTime:    out.UNIXTime,
					Kind:        kind,
					Row:         r,
					VirusTotal:  vt,
				}

				if out.KolideDecorations.DeviceOwnerEmail != "" {
					row.Decorations["device_owner_email"] = out.KolideDecorations.DeviceOwnerEmail
				}
				if out.KolideDecorations.DeviceOwnerType != "" {
					row.Decorations["device_owner_type"] = out.KolideDecorations.DeviceOwnerType
				}
				if out.KolideDecorations.DeviceOwnerEmail != "" {
					row.Decorations["device_display_name"] = out.KolideDecorations.DeviceDisplayName
				}

				rows = append(rows, row)
			}
			seen[msg] = true
		}
	}

	klog.Infof("collection complete: %d rows found", len(rows))
	return rows
}
