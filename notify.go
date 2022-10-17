package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/multiplay/go-slack/chat"
	"github.com/multiplay/go-slack/webhook"
	"k8s.io/klog/v2"
)

var (
	fuzzyIPValue   = regexp.MustCompile(`([\/:])\d+\.[\d\.]+`)
	fuzzyAlphaNum  = regexp.MustCompile(`\w+\d+[a-zA-Z]+[\w_-]+`)
	fuzzyNumValue  = regexp.MustCompile(`(:)\d+`)
	fuzzyDateIntro = regexp.MustCompile(` at \d+ \w+ \d+.*`)

	// Suppress duplicate messages within this time period
	maxDupeTime = time.Hour * 13
)

func NewNotifier() Notifier {
	return Notifier{
		lastNotification: map[string]time.Time{},
	}
}

type Notifier struct {
	lastNotification map[string]time.Time
}

// isDuplicate checks if the message is an exact duplicate or a fuzzy duplicate
func (n *Notifier) recentDupe(msg string) bool {
	munged := mungeMsg(msg)
	klog.Infof("last notice: %s for %s", n.lastNotification[munged], munged)
	return time.Since(n.lastNotification[munged]) < maxDupeTime
}

// saveMsg saves messages for the duplicate detector
func (n *Notifier) saveMsg(msg string) {
	munged := mungeMsg(msg)
	n.lastNotification[munged] = time.Now()
}

// mungeMsg munges a message for the duplicate detector
func mungeMsg(msg string) string {
	new := fuzzyIPValue.ReplaceAllString(msg, "$1<ip>")
	new = fuzzyAlphaNum.ReplaceAllString(new, "<alphanum>")
	new = fuzzyNumValue.ReplaceAllString(new, "$1<num>")
	new = fuzzyDateIntro.ReplaceAllString(new, "<date>")
	return new
}

func (n *Notifier) Notify(url string, row DecoratedRow) error {
	t := time.Unix(row.UNIXTime, 0)

	id := row.Decorations["hardware_serial"]
	if row.Decorations["device_owner_email"] != "" {
		id, _, _ = strings.Cut(row.Decorations["device_owner_email"], "@")
		id = id + "@"
	}

	klog.Infof("decorations: %+v", row.Decorations)

	text := fmt.Sprintf("*%s* on %s at %s (%s):\n> %s", row.Kind, row.Decorations["computer_name"], t.Format(time.RFC822), id, row.Row)
	if len(row.VirusTotal) > 0 {
		text = text + "\n\n" + row.VirusTotal.String()
	}

	if n.recentDupe(text) {
		el := text
		if len(el) > 160 {
			el = el[0:160] + "..."
		}
		klog.Infof("skipping recent duplicate message: %s", el)
		return nil
	}

	klog.Infof("### NOTIFY: %s", text)
	n.saveMsg(text)

	if url == "" {
		return nil
	}

	c := webhook.New(url)
	m := &chat.Message{Text: text}

	klog.Infof("Sending to %s: %+v", url, c)
	resp, err := m.Send(c)

	if resp.Message != nil || resp.Warning != "" || resp.Error != "" {
		klog.Infof("response: %+v err=%v", resp, err)
	}
	return err
}
