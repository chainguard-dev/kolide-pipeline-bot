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
		bucket:            sc.Bucket,
		prefix:            sc.Prefix,
		webhookURL:        sc.WebhookURL,
		notifier:          NewNotifier(),
		lastRefresh:       sc.Cutoff,
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
	Prefix            string
	WebhookURL        string
	Cutoff            time.Time
	Addr              string
	MaxNoticesPerKind int
	VirusTotalClient  *vt.Client
}

type Server struct {
	bucket            *storage.BucketHandle
	prefix            string
	webhookURL        string
	notifier          Notifier
	lastRefresh       time.Time
	lastNotification  map[string]time.Time
	maxNoticesPerKind int
	vtc               *vt.Client
}

func (s *Server) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.URL)
		duration := time.Since(s.lastRefresh)

		rows := getRows(r.Context(), s.bucket, s.prefix, s.lastRefresh, s.vtc)
		klog.Infof("collected %d rows", len(rows))
		// lol race
		s.lastRefresh = time.Now()
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
