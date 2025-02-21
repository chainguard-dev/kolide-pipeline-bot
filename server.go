package main

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"cloud.google.com/go/vertexai/genai"
	"github.com/VirusTotal/vt-go"
	"github.com/slack-go/slack"
	"k8s.io/klog/v2"
)

func Serve(_ context.Context, sc *Config) {
	s := &Server{
		collectConfig:     sc.CollectConfig,
		bucket:            sc.Bucket,
		slack:             sc.SlackClient,
		channel:           sc.Channel,
		notifier:          NewNotifier(),
		maxNoticesPerKind: sc.MaxNoticesPerKind,
		lastNotification:  map[string]time.Time{},
		vtc:               sc.VirusTotalClient,
		model:             sc.VertexModel,
		pq:                map[string][]*DecoratedRow{},
	}
	http.HandleFunc("/refreshz", s.Refresh())
	http.HandleFunc("/x-healthz", s.Healthz())
	http.HandleFunc("/x-threadz", s.Threadz())
	klog.Infof("Config: %+v", sc)
	klog.Infof("Listening on %s ...", sc.Addr)
	if err := http.ListenAndServe(sc.Addr, nil); err != nil {
		klog.Fatalf("serve failed: %v", err)
	}
}

type Config struct {
	Bucket            *storage.BucketHandle
	CollectConfig     *CollectConfig
	Addr              string
	SlackClient       *slack.Client
	Channel           string
	MaxNoticesPerKind int
	VirusTotalClient  *vt.Client
	VertexModel       *genai.GenerativeModel
}

type Server struct {
	bucket            *storage.BucketHandle
	channel           string
	slack             *slack.Client
	collectConfig     *CollectConfig
	notifier          Notifier
	lastCollection    time.Time
	lastNotification  map[string]time.Time
	maxNoticesPerKind int
	vtc               *vt.Client
	running           sync.Mutex
	model             *genai.GenerativeModel
	pq                map[string][]*DecoratedRow
}

func (s *Server) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		klog.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.URL)

		klog.Infof("attempting to lock the mutex ...")
		s.running.Lock()
		defer func() {
			klog.Infof("unlocking mutex ...")
			s.running.Unlock()
			klog.Infof("mutex unlocked")
		}()
		klog.Infof("refresh mutex locked")

		duration := time.Since(s.lastCollection)
		if s.lastCollection.After(s.collectConfig.Cutoff) {
			// Go backwards to avoid TOCTOU races
			s.collectConfig.Cutoff = s.lastCollection.Add(time.Second * -1)
			klog.Infof("Using %s as new cutoff time based on the previous refresh", s.collectConfig.Cutoff)
		}

		refreshStartedAt := time.Now()
		rows := getRows(ctx, s.bucket, s.vtc, s.collectConfig)
		klog.Infof("collected %d rows", len(rows))

		// Record the last refresh as the time just before getRows() is called,
		// so that future runs don't miss records written during getRows() execution
		if len(rows) > 0 {
			s.lastCollection = refreshStartedAt
			klog.Infof("Recording last successful refresh as %s", refreshStartedAt)
		}

		total := map[string]int{}

		klog.Infof("processing %d rows ...", len(rows))
		for _, r := range rows {
			total[r.Kind]++
			if total[r.Kind] > s.maxNoticesPerKind {
				klog.Warningf("notification overflow for %s (%d), will not notify for: %s", r.Kind, total[r.Kind], r.Row)
				continue
			}

			if err := scoreRow(ctx, s.model, r); err != nil {
				klog.Errorf("score: %v", err)
			}
			enqueueRow(ctx, s.pq, r)
		}

		matches := priorityDevices(s.pq, 2)
		klog.Infof("devices to notify for: %v", matches)

		notifications := 0
		for _, d := range matches {
			rows := s.pq[d]
			sort.Slice(rows, func(i, j int) bool {
				return rows[i].Score > rows[j].Score
			})

			for _, r := range rows {
				if err := s.notifier.Notify(s.slack, s.channel, *r); err != nil {
					klog.Errorf("notify error: %v", err)
				}
				notifications++
			}

			klog.Infof("emptying priority queue for %s", d)
			s.pq[d] = []*DecoratedRow{}
		}

		w.WriteHeader(http.StatusOK)
		out := fmt.Sprintf("%d events, %d notifications in %s", len(rows), notifications, duration)
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
