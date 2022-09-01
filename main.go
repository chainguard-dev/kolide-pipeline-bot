// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// [START storage_quickstart]

// Sample storage-quickstart creates a Google Cloud Storage bucket.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/multiplay/go-slack/chat"
	"github.com/multiplay/go-slack/webhook"
	"google.golang.org/api/iterator"
	"k8s.io/klog/v2"
)

var (
	bucketFlag     = flag.String("bucket", "", "Bucket to query")
	prefixFlag     = flag.String("prefix", "", "directory of contents to query")
	webhookURLFlag = flag.String("webhook-url", "", "Slack webhook URL to hit")
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
	// launchd
	p, ok := r["program_arguments"]
	if ok {
		return fmt.Sprintf("%s: %s", r["path"], p)
	}

	// listening_ports
	addr, ok := r["address"]
	if ok {
		return fmt.Sprintf("%s in %s listening at [%s]:%s (%s): %s", r["name"], r["cwd"], addr, r["port"], r["protocol"], r["cmdline"])
	}

	addr, ok = r["remote_address"]
	if ok {
		return fmt.Sprintf("%s in %s talking to [%s]:%s (%s): %s", r["name"], r["cwd"], addr, r["remote_port"], r["protocol"], r["cmdline"])
	}

	// file paths
	if _, ok = r["atime"]; ok {
		return fmt.Sprintf("%s (%s)", r["path"], r["type"])
	}

	// processes
	if _, ok := r["cmdline"]; ok {
		return fmt.Sprintf("name=%s path=%s cmdline=%s cwd=%s", r["name"], r["path"], r["cmdline"], r["cwd"])
	}

	var sb strings.Builder
	for k, v := range r {
		sb.WriteString(fmt.Sprintf("%s=%s ", k, v))
	}

	return sb.String()
}

func getRows(ctx context.Context, bucket *storage.BucketHandle, prefix string, cutoff time.Time) []DecoratedRow {
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
			klog.Errorf("Bucket(%q).Objects: %v", bucket, err)
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
	m := &chat.Message{Text: fmt.Sprintf("*%s* on %s:\n`%s`", row.Kind, row.Decorations["computer_name"], row.Row)}
	resp, err := m.Send(c)
	klog.Infof("response: %+v err=%v", resp, err)
	return err
}

func main() {
	flag.Parse()

	ctx := context.Background()

	cutoff := time.Now().Add(-40 * time.Minute)

	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Creates a Bucket instance.
	bucket := client.Bucket(*bucketFlag)

	rows := getRows(ctx, bucket, *prefixFlag, cutoff)
	klog.Infof("collected %d rows", len(rows))

	if *webhookURLFlag != "" {
		for _, r := range rows {
			if err := notify(*webhookURLFlag, r); err != nil {
				klog.Errorf("notify error: %v", err)
			}
		}
	}
}
