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
	DiffResults diffResults       `json:"diffResults"`
	Name        string            `json:"name"`
	Decorations map[string]string `json:"decorations"`
	UNIXTime    int64             `json:"unixTime"`
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
	VirusTotal  Row
}

func (r Row) String() string {
	var sb strings.Builder
	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := r[k]
		if len(v) > 384 {
			v = v[0:384] + "..."
		}
		sb.WriteString(fmt.Sprintf(`%s=%q `, k, v))
	}
	return strings.TrimSpace(sb.String())
}

func getRows(ctx context.Context, bucket *storage.BucketHandle, prefix string, cutoff time.Time, vtc *vt.Client) []DecoratedRow {
	klog.Infof("querying bucket for items matching prefix %q ...", prefix)
	it := bucket.Objects(ctx, &storage.Query{Prefix: prefix})
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

		if attrs.Created.Before(cutoff) {
			continue
		}

		rc, err := bucket.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			klog.Fatal(err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			klog.Fatal(err)
		}

		out := &OutFile{}
		err = json.Unmarshal(body, out)
		if err != nil {
			out2 := []OutFile{}
			err2 := json.Unmarshal(body, &out2)
			if err2 != nil {
				klog.Errorf("unmarshal(%s): %v\nsecond attempt: %v", body, err, err2)
				continue
			}
			klog.Warningf("Recovered array-based body (%d elements)", len(out2))
			out = &out2[0]
		}

		kind := filepath.Base(filepath.Dir(filepath.Dir(attrs.Name)))
		if kind != lastKind {
			klog.Infof("=== kind: %s ===", kind)
			lastKind = kind
		}

		for _, r := range out.DiffResults.Added {
			msg := fmt.Sprintf("%s/%s: %s", kind, out.Decorations["computer_name"], r)
			if !seen[msg] {
				klog.Infof(msg)
				vt, err := vtMetadata(r, vtc)
				if err != nil {
					klog.Errorf("failed to fetch VT metadata: %v", err)
				}

				rows = append(rows, DecoratedRow{
					Decorations: out.Decorations,
					UNIXTime:    out.UNIXTime,
					Kind:        kind,
					Row:         r,
					VirusTotal:  vt,
				})
			}
			seen[msg] = true
		}
	}

	return rows
}
