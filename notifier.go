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
	"github.com/multiplay/go-slack/chat"
	"github.com/multiplay/go-slack/webhook"
	"google.golang.org/api/iterator"
	"k8s.io/klog/v2"
)

type OutFile struct {
	DiffResults diffResults       `json:"diffResults"`
	Name        string            `json:"name"`
	Decorations map[string]string `json:"decorations"`
	UNIXTime    int               `json:"unixTime"`
}

type diffResults struct {
	Removed []Row
	Added   []Row
}

type Row map[string]string

type DecoratedRow struct {
	Decorations map[string]string
	Kind        string
	UNIXTime    int
	Row         Row
}

func (r Row) String() string {
	var sb strings.Builder
	for k, v := range r {
		sb.WriteString(fmt.Sprintf(`%s=%q `, k, v))
	}
	return strings.TrimSpace(sb.String())
}

func getRows(ctx context.Context, bucket *storage.BucketHandle, prefix string, cutoff time.Time) []DecoratedRow {
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
			klog.Fatalf("unmarshal: %+v", err)
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
				rows = append(rows, DecoratedRow{Decorations: out.Decorations, UNIXTime: out.UNIXTime, Kind: kind, Row: r})
			}
			seen[msg] = true
		}
	}

	return rows
}

func notify(url string, row DecoratedRow) error {
	c := webhook.New(url)
	m := &chat.Message{Text: fmt.Sprintf("*%s* on %s:\n> %s", row.Kind, row.Decorations["computer_name"], row.Row)}
	resp, err := m.Send(c)

	if resp.Message != nil || resp.Warning != "" || resp.Error != "" {
		klog.Infof("response: %+v err=%v", resp, err)
	}
	return err
}
