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
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"k8s.io/klog/v2"
)

var (
	bucketFlag     = flag.String("bucket", "", "Bucket to query")
	prefixFlag     = flag.String("prefix", "", "directory of contents to query")
	webhookURLFlag = flag.String("webhook-url", "", "Slack webhook URL to hit")
	serveFlag      = flag.Bool("serve", false, "")
	maxAgeFlag     = flag.Duration("max-age", 10*time.Minute, "Maximum age of events to include")
	maxNoticesFlag = flag.Int("max-notices-per-kind", 5, "Maximum notices per kind (spam reduction)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	cutoff := time.Now().Add(*maxAgeFlag * -1)

	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucketName := os.Getenv("BUCKET_NAME")
	if *bucketFlag != "" {
		bucketName = *bucketFlag
	}

	// Creates a Bucket instance.
	bucket := client.Bucket(bucketName)

	bucketPrefix := os.Getenv("BUCKET_PREFIX")
	if *prefixFlag != "" {
		bucketPrefix = *prefixFlag
	}

	webhookURL := os.Getenv("WEBHOOK_URL")
	if *webhookURLFlag != "" {
		webhookURL = *webhookURLFlag
	}

	if *serveFlag {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		Serve(ctx, &Config{
			Bucket:            bucket,
			Prefix:            bucketPrefix,
			WebhookURL:        webhookURL,
			Cutoff:            cutoff,
			Addr:              fmt.Sprintf(":%s", port),
			MaxNoticesPerKind: *maxNoticesFlag,
		})
	}

	rows := getRows(ctx, bucket, bucketPrefix, cutoff)
	klog.Infof("collected %d rows", len(rows))

	total := map[string]int{}

	if webhookURL != "" {
		for _, r := range rows {
			total[r.Kind]++
			if total[r.Kind] > *maxNoticesFlag {
				klog.Warningf("notification overflow for %s (%d), will not notify for: %s", r.Kind, total[r.Kind], r.Row)
				continue
			}
			if err := notify(webhookURL, r); err != nil {
				klog.Errorf("notify error: %v", err)
			}
		}
	}

}
