package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
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
	Decorations    map[string]string
	Kind           string
	UNIXTime       int64
	Row            Row
	VirusTotal     VTRow
	Score          int
	Interpretation string
	Source         string
}

type CollectConfig struct {
	Prefix         string
	Cutoff         time.Time
	ExcludeSubdirs []string
}

func getRows(ctx context.Context, bucket *storage.BucketHandle, vtc *vt.Client, cc *CollectConfig) []*DecoratedRow {
	start := time.Now()
	klog.Infof("finding items matching: %+v ...", cc)

	q := &storage.Query{Prefix: cc.Prefix}
	q.SetAttrSelection([]string{"Name", "Created", "Size"})
	it := bucket.Objects(ctx, q)
	lastKind := ""

	rows := []*DecoratedRow{}
	seen := map[string]bool{}
	maxEmptySize := int64(256)

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			klog.Errorf("error fetching objects: %v", err)
			break
		}

		kind := filepath.Base(filepath.Dir(filepath.Dir(attrs.Name)))
		if kind != lastKind {
			klog.Infof("searching %q ...", kind)
			lastKind = kind
			maxEmptySize = 0
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

		if attrs.Size <= maxEmptySize {
			klog.V(1).Infof("skipping %s -- smaller than %d bytes", attrs.Name, attrs.Size)
			continue
		}

		klog.V(1).Infof("reading: %+v (%d bytes)", attrs.Name, attrs.Size)
		rc, err := bucket.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			klog.Fatal(err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			klog.Fatal(err)
		}

		out := OutFile{}
		err = json.Unmarshal(body, &out)

		if len(out.DiffResults.Added) == 0 && len(out.DiffResults.Removed) == 0 {
			if attrs.Size > int64(maxEmptySize) {
				maxEmptySize = attrs.Size
				klog.V(1).Infof("new min size: %d - %s", maxEmptySize, body)
			}
		}

		for _, r := range out.DiffResults.Added {
			msg := fmt.Sprintf("%s/%s (%+v): %s", kind, out.Decorations["computer_name"], out.KolideDecorations, r)
			if seen[msg] {
				klog.Infof("ignoring seen msg: %s", msg)
				continue
			}

			klog.Infof("diff added: %s", msg)
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
				Source:      attrs.Name,
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

			rows = append(rows, &row)
			seen[msg] = true
		}
	}

	klog.Infof("collection complete: %d rows found in %s", len(rows), time.Since(start))
	return rows
}
