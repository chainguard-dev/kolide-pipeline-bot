package main

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"cloud.google.com/go/storage"
	"github.com/VirusTotal/vt-go"
	"k8s.io/klog/v2"
)

func Serve(_ context.Context, sc *Config) {
	s := &Server{
		collectConfig:     sc.CollectConfig,
		bucket:            sc.Bucket,
		webhookURL:        sc.WebhookURL,
		notifier:          NewNotifier(),
		maxNoticesPerKind: sc.MaxNoticesPerKind,
		lastNotification:  map[string]time.Time{},
		vtc:               sc.VirusTotalClient,
	}
	http.HandleFunc("/refreshz", s.Refresh())
	http.HandleFunc("/healthz", s.Healthz())
	http.HandleFunc("/threadz", s.Threadz())
	klog.Infof("Config: %+v", sc)
	klog.Infof("Listening on %s ...", sc.Addr)
	if err := http.ListenAndServe(sc.Addr, nil); err != nil {
		klog.Fatalf("serve failed: %v", err)
	}
}

type Config struct {
	Bucket            *storage.BucketHandle
	CollectConfig     *CollectConfig
	WebhookURL        string
	Addr              string
	MaxNoticesPerKind int
	VirusTotalClient  *vt.Client
}

type Server struct {
	bucket            *storage.BucketHandle
	collectConfig     *CollectConfig
	webhookURL        string
	notifier          Notifier
	lastCollection    time.Time
	lastNotification  map[string]time.Time
	maxNoticesPerKind int
	vtc               *vt.Client
}

func (s *Server) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.URL)
		duration := time.Since(s.lastCollection)
		if s.lastCollection.After(s.collectConfig.Cutoff) {
			// Go backwards to avoid TOCTOU races
			s.collectConfig.Cutoff = s.lastCollection.Add(time.Second * -1)
			klog.Infof("Using %s as new cutoff time based on the previous refresh", s.collectConfig.Cutoff)
		}

		refreshStartedAt := time.Now()
		rows := getRows(r.Context(), s.bucket, s.vtc, s.collectConfig)
		klog.Infof("collected %d rows", len(rows))

		// Record the last refresh as the time just before getRows() is called,
		// so that future runs don't miss records written during getRows() execution
		if len(rows) > 0 {
			s.lastCollection = refreshStartedAt
			klog.Infof("Recording last successful refresh as %s", refreshStartedAt)
		}

		total := map[string]int{}

		for _, r := range rows {
			total[r.Kind]++
			if total[r.Kind] > s.maxNoticesPerKind {
				klog.Warningf("notification overflow for %s (%d), will not notify for: %s", r.Kind, total[r.Kind], r.Row)
				continue
			}

			if err := s.notifier.Notify(s.webhookURL, r); err != nil {
				klog.Errorf("notify error: %v", err)
				continue
			}

		}

		w.WriteHeader(http.StatusOK)
		out := fmt.Sprintf("%d events -- %s", len(rows), duration)
		if _, err := w.Write([]byte(out)); err != nil {
			klog.Errorf("writing threadz response: %d", err)
		}

	}
}

func (s *Server) Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) Threadz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.Infof("GET %s: %v", r.URL.Path, r.Header)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(stack()); err != nil {
			klog.Errorf("writing threadz response: %d", err)
		}
	}
}

func stack() []byte {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
