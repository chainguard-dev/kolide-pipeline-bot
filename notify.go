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
	fuzzyIPValue = regexp.MustCompile(`\d+\.[\d\.]+`)
	// good enough
	fuzzyIPv6Value = regexp.MustCompile(`'*[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[[0-9a-f:]+'*`)
	fuzzyAlphaNum  = regexp.MustCompile(`\w+\d+[a-zA-Z]+[\w_-]+`)
	fuzzyNumValue  = regexp.MustCompile(`\d+`)
	fuzzyDateIntro = regexp.MustCompile(` at \d+ \w+ \d+.*`)
	nonAlpha       = regexp.MustCompile(`\W+`)

	// Suppress duplicate messages within this time period
	maxDupeTime = time.Hour * 24 * 3
	// Follow-up to threads that are within this time period
	maxRelatedThreadMatch   = time.Hour * 24 * 1
	maxUnrelatedThreadMatch = time.Hour

	// Keys to use for finding related threads
	relateKeys = []string{
		"path",
		"child_path",
		"p0_path",
		"p0_cmd",
		"cmd",
		"cmdline",
		"ctime",
		"mtime",
		"start_time",
		"exception_key",
		"p0_sha256",
		"child_sha256",
		"child_cmd",
		"parent",
		"p0_parent",
		"sha256",
		"id",
		"name",
		"remote_address",
		"pid",
		"p0_pid",
	}
)

func NewNotifier() Notifier {
	return Notifier{
		lastNotification: map[string]time.Time{},
		threads:          map[string][]*Thread{},
	}
}

type Notifier struct {
	lastNotification map[string]time.Time
	// map of username -> Thread
	threads map[string][]*Thread
}

type Thread struct {
	Updated   time.Time
	Relations map[string]string
	Kinds     map[string]bool
	ID        string
}

// rowRelations picks out the row columns important for determining if a thread is related
func rowRelations(row DecoratedRow) map[string]string {
	relations := map[string]string{}
	for _, r := range relateKeys {
		if row.Row[r] != "" {
			relations[r] = row.Row[r]
		}
	}
	relations["kind"] = row.Kind
	return relations
}

// findThread finds the most relevant thread to follow-up on
func (n *Notifier) findThread(user string, relations map[string]string) (*Thread, []string) {
	var mostRecent *Thread
	var related *Thread
	var via []string

	klog.V(1).Infof("finding thread for %s matching %+v", user, relations)
	// Rough logic:
	//
	// - prefer recent threads that contain the same path
	// - fallback to recent threads that contain the same alert
	// - fallback to very recent threads for the same user
	for _, t := range n.threads[user] {
		t := t
		matches := []string{}

		for k, v := range t.Relations {
			for rk, rv := range relations {
				if v != rv {
					continue
				}

				matches = append(matches, fmt.Sprintf("%s=%s", k, rk))
			}
		}

		if len(matches) > 0 && (related == nil || related.Updated.Before(t.Updated)) {
			related = t
			klog.V(1).Infof("newer thread via %s: %+v", matches, related)
			via = matches
		}

		if mostRecent == nil || mostRecent.Updated.Before(t.Updated) {
			mostRecent = t
		}
	}

	if related != nil && time.Since(related.Updated) < maxRelatedThreadMatch {
		return related, via
	}

	// If the user has a thread within the last hour, follow-up there
	// If not, use the last known thread with the same path.
	if mostRecent != nil && time.Since(mostRecent.Updated) < maxUnrelatedThreadMatch {
		return mostRecent, []string{"recency"}
	}

	return nil, nil
}

// saveThread saves a thread for later follow-up
func (n *Notifier) saveThread(user string, row DecoratedRow, ts string) {
	relations := rowRelations(row)
	found, via := n.findThread(user, relations)
	if found == nil {
		t := &Thread{Updated: time.Now(), Relations: relations, ID: ts}
		n.threads[user] = append(n.threads[user], t)
		klog.V(1).Infof("saved %s thread: %+v", user, t)
		return
	}

	found.Updated = time.Now()
	for k, v := range relations {
		if found.Relations[k] != "" {
			found.Relations[k] = v
		}
	}
	klog.V(1).Infof("updated %s thread matched via %s: %+v", user, via, found)
}

// isDuplicate checks if the message is an exact duplicate or a fuzzy duplicate
func (n *Notifier) recentDupe(msg string) bool {
	munged := mungeMsg(msg)
	if n.lastNotification[munged].IsZero() {
		klog.V(1).Infof("no dupe for %s", munged)
		return false
	}
	klog.Infof("found dupe @ %s for %s", n.lastNotification[munged], munged)
	return time.Since(n.lastNotification[munged]) < maxDupeTime
}

// saveMsg saves messages for the duplicate detector
func (n *Notifier) saveMsg(msg string) {
	munged := mungeMsg(msg)
	klog.V(1).Infof("saving munged: %s", munged)
	n.lastNotification[munged] = time.Now()
}

// mungeMsg munges a message for the duplicate detector
func mungeMsg(msg string) string {
	new := fuzzyIPValue.ReplaceAllString(msg, "<ip>")
	new = fuzzyIPv6Value.ReplaceAllString(new, "<ip>")
	new = fuzzyDateIntro.ReplaceAllString(new, "<date>")
	new = fuzzyAlphaNum.ReplaceAllString(new, "<alphanum>")
	new = fuzzyNumValue.ReplaceAllString(new, "<num>")
	new = nonAlpha.ReplaceAllString(new, " ")
	return new
}

func (n *Notifier) Notify(url string, row DecoratedRow) error {
	t := time.Unix(row.UNIXTime, 0)

	id := row.Decorations["hardware_serial"]
	if row.Decorations["device_owner_email"] != "" {
		id, _, _ = strings.Cut(row.Decorations["device_owner_email"], "@")
		id = id + "@"
	}

	device := row.Decorations["computer_name"]
	if _, ok := n.threads[device]; !ok {
		n.threads[device] = []*Thread{}
	}

	klog.V(1).Infof("decorations: %+v", row.Decorations)

	text := fmt.Sprintf("*%s* on %s at %s (%s):\n> %s", row.Kind, row.Decorations["computer_name"], t.Format(time.RFC822), id, row.Row)
	if len(row.VirusTotal) > 0 {
		text = text + "\n\n" + row.VirusTotal.String()
	}

	if n.recentDupe(text) {
		klog.Infof("suppressing recent dupe: %s", text)
		return nil
	}

	m := &chat.Message{Text: text}
	relations := rowRelations(row)
	thread, via := n.findThread(device, relations)

	if thread != nil {
		klog.Infof("found %s thread via %s: %+v", device, via, thread)
		m.Text = m.Text + fmt.Sprintf("\n\n> related via %s", strings.Join(via, " "))
		m.ThreadTS = thread.ID
	} else {
		klog.V(1).Infof("no threads for %s matching %+v", device, relations)
	}

	klog.Infof("### NOTIFY[%s]: %s", m.ThreadTS, m.Text)
	n.saveMsg(text)

	// fake threading
	if url == "" {
		n.saveThread(device, row, fmt.Sprintf("%d", time.Now().Unix()))
		return nil
	}

	c := webhook.New(url)

	klog.Infof("Sending to %s: %+v", url, c)
	resp, err := m.Send(c)
	klog.Infof("response: %+v", resp)
	if resp.Timestamp != "" {
		n.saveThread(device, row, resp.Timestamp)
	}

	if resp.Message != nil || resp.Warning != "" || resp.Error != "" {
		klog.Infof("response: %+v err=%v", resp, err)
	}

	return err
}
