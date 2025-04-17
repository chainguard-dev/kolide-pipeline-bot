package main

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
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
	aiText         = regexp.MustCompile(`AI: .*`)

	// Suppress duplicate messages within this time period
	maxDupeTime = time.Hour * 24 * 5
	// Follow-up to threads that are within this time period
	relationTime    = time.Hour
	maxRelationTime = time.Hour * 12
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
			klog.Infof("found thread for %s via %s: %+v", user, matches, related)
			via = matches
		}

		if mostRecent == nil || mostRecent.Updated.Before(t.Updated) {
			mostRecent = t
		}
	}

	if related == nil && mostRecent != nil {
		related = mostRecent
		klog.Infof("found thread for %s via recently: %+v", user, related)
		via = append(via, "recency")
	}

	score := int(math.Ceil(math.Pow(float64(len(via)), 2) / 3))

	threadMatchTime := relationTime * time.Duration(len(via))
	if threadMatchTime > maxRelationTime {
		threadMatchTime = maxRelationTime
	}

	if related != nil {
		if time.Since(related.Updated) < threadMatchTime {
			return related, via
		} else {
			klog.Infof("found similar thread with %d score (%s), but %s is older than %s", score, via, time.Since(related.Updated), threadMatchTime)
		}
	}

	klog.Infof("%s: among %d threads, no obvious candidates to follow-up on", user, len(n.threads[user]))
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

	// Add new relation tags if they do not conflict with existing ones.
	for k, v := range relations {
		if found.Relations[k] == "" {
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
		klog.Infof("no dupe of %s", munged)
		return false
	}

	age := time.Since(n.lastNotification[munged])
	if age < maxDupeTime {
		klog.Infof("fresh dupe @ %s for %s [age=%s]", n.lastNotification[munged], munged, age)
		return true
	}

	klog.Infof("stale dupe @ %s for %s [age=%s]", n.lastNotification[munged], munged, age)
	return false
}

// saveMsg saves messages for the duplicate detector
func (n *Notifier) saveMsg(msg string) {
	munged := mungeMsg(msg)
	klog.V(1).Infof("saving munged: %s", munged)
	n.lastNotification[munged] = time.Now()
}

// mungeMsg munges a message for the duplicate detector
func mungeMsg(msg string) string {
	new := fuzzyIPValue.ReplaceAllString(msg, "")
	new = aiText.ReplaceAllString(new, "")
	new = fuzzyIPv6Value.ReplaceAllString(new, "")
	new = fuzzyDateIntro.ReplaceAllString(new, "")
	new = fuzzyAlphaNum.ReplaceAllString(new, "")
	new = fuzzyNumValue.ReplaceAllString(new, "")
	new = nonAlpha.ReplaceAllString(new, " ")

	uniq := map[string]bool{}
	for _, word := range strings.Split(new, " ") {
		if len(word) > 2 {
			uniq[word] = true
		}
	}

	parts := []string{}
	for k := range uniq {
		parts = append(parts, k)
	}
	sort.Strings(parts)
	return strings.Join(parts, "/")
}

func messageText(msg *slack.Message) string {
	// the text seems to be hidden away in private structs, so we marshal it out?
	j, err := json.Marshal(msg.Msg.Blocks.BlockSet)
	if err != nil {
		panic(fmt.Sprintf("unable to marshal: %v", err))
	}
	return string(j)
}

func (n *Notifier) Notify(s *slack.Client, channel string, row DecoratedRow) error {
	device := row.Decorations["computer_name"]
	if _, ok := n.threads[device]; !ok {
		n.threads[device] = []*Thread{}
	}

	message := Format(MessageInput{Row: row}, true)
	text := messageText(message)
	if n.recentDupe(text) {
		klog.Infof("suppressing recent dupe: %s", text)
		return nil
	}

	thread, via := n.findThread(device, rowRelations(row))
	threadID := ""

	if thread != nil {
		message = Format(MessageInput{Row: row, Via: via}, true)
		threadID = thread.ID
	}

	n.saveMsg(text)

	// fake threading
	if s == nil {
		klog.Infof("### FAKE MSG[thread=%s]: %s", threadID, text)
		n.saveThread(device, row, text, fmt.Sprintf("%d", time.Now().Unix()))
		return nil
	}

	// we do this very late because string functions that return ``` is not fun.
	text = strings.ReplaceAll(text, "---", "```")
	klog.Infof("### POST[thread=%s]: %s", threadID, text)
	ch, ts, err := s.PostMessage(channel,
		slack.MsgOptionBlocks(message.Msg.Blocks.BlockSet...),
		slack.MsgOptionAsUser(true),
		slack.MsgOptionTS(threadID),
		slack.MsgOptionDisableLinkUnfurl(),
	)
	klog.Infof("postmessage returned: ch=%s ts=%s err=%v", ch, ts, err)

	if err != nil {
		klog.Errorf("SEND FAILED for %s/%s: %v", row.Kind, device, err)
		message = Format(MessageInput{Row: row, Via: via}, false)
		text := messageText(message)
		klog.Infof("### POST AGAIN[thread=%s]: %s", threadID, text)
		ch, ts, err := s.PostMessage(channel,
			slack.MsgOptionBlocks(message.Msg.Blocks.BlockSet...),
			slack.MsgOptionAsUser(true),
			slack.MsgOptionTS(threadID),
			slack.MsgOptionDisableLinkUnfurl(),
		)
		klog.Infof("postmessage again returned: ch=%s ts=%s err=%v", ch, ts, err)
	}

	if ts != "" {
		n.saveThread(device, row, text, ts)
	}

	return err
}
