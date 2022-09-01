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
)

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

	if *serveFlag {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		Serve(ctx, &Config{
			Bucket:     bucket,
			Prefix:     *prefixFlag,
			WebhookURL: *webhookURLFlag,
			Cutoff:     cutoff,
			Addr:       fmt.Sprintf(":%s", port),
		})
	}

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
