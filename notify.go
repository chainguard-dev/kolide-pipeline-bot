package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/slack-go/slack"
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
	maxDupeTime = time.Hour * 24 * 1
	// Follow-up to threads that are within this time period
	relationTime = time.Hour
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
	Text      string
	Munged    string
}

// rowRelations picks out the row columns important for determining if a thread is related
func rowRelations(row DecoratedRow) map[string]string {
	relations := map[string]string{}
	for k, v := range row.Row {
		if len(v) > 1 {
			relations[k] = strings.TrimSpace(v)
		}
	}
	relations["__kind"] = row.Kind
	relations["__time"] = fmt.Sprintf("%d", row.UNIXTime)
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

	if related == nil && mostRecent != nil {
		related = mostRecent
		via = append(via, "recency")
	}

	score := len(via)
	if score > 6 {
		score = score * 2
	}
	threadMatchTime := relationTime * time.Duration(len(via))
	if related != nil {
		if time.Since(related.Updated) < threadMatchTime {
			return related, via
		} else {
			klog.Infof("found similar thread with %d score (%s), but %s is older than %s", score, via, time.Since(related.Updated), threadMatchTime)
		}
	}

	return nil, nil
}

// saveThread saves a thread for later follow-up
func (n *Notifier) saveThread(user string, row DecoratedRow, text, ts string) *Thread {
	relations := rowRelations(row)
	found, via := n.findThread(user, relations)
	if found == nil {
		t := &Thread{
			Updated:   time.Now(),
			Relations: relations,
			ID:        ts,
			Text:      text,
			Munged:    mungeMsg(text),
		}
		n.threads[user] = append(n.threads[user], t)
		klog.V(1).Infof("saved %s thread: %+v", user, t)
		return t
	}

	found.Updated = time.Now()
	for k, v := range relations {
		if found.Relations[k] != "" {
			found.Relations[k] = v
		}
	}
	klog.V(1).Infof("updated %s thread matched via %s: %+v", user, via, found)
	return found
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

func (n *Notifier) Notify(s *slack.Client, channel string, row DecoratedRow) error {
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

	relations := rowRelations(row)
	thread, via := n.findThread(device, relations)
	threadID := ""

	if thread != nil {
		klog.Infof("found %s thread via %s: %+v", device, via, thread)
		text = text + fmt.Sprintf("\n\n> related via %s", strings.Join(via, " "))
		threadID = thread.ID
	} else {
		klog.V(1).Infof("no threads for %s matching %+v", device, relations)
	}

	n.saveMsg(text)

	// fake threading
	if s == nil {
		klog.Infof("### FAKE MSG[thread=%s]: %s", threadID, text)
		n.saveThread(device, row, text, fmt.Sprintf("%d", time.Now().Unix()))
		return nil
	}

	klog.Infof("### POSTING MSG[thread=%s]: %s", threadID, text)
	ch, ts, err := s.PostMessage(channel, slack.MsgOptionText(text, false), slack.MsgOptionAsUser(true), slack.MsgOptionTS(threadID))
	klog.Infof("postmessage: ch=%s ts=%s err=%v", ch, ts, err)
	if ts != "" {
		n.saveThread(device, row, text, ts)
	}

	return err
}
