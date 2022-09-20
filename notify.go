package main

import (
	"fmt"
	"time"

	"github.com/mergestat/timediff"
	"github.com/multiplay/go-slack/chat"
	"github.com/multiplay/go-slack/webhook"
	"k8s.io/klog/v2"
)

func notify(url string, row DecoratedRow) error {
	t := time.Unix(row.UNIXTime, 0)
	diff := timediff.TimeDiff(t)

	text := fmt.Sprintf("*%s* on %s at %s (%s ago):\n> %s", row.Kind, row.Decorations["computer_name"], t, diff, row.Row)
	if len(row.VirusTotal) > 0 {
		text = text + fmt.Sprintf("\n\n> VT: %s", row.VirusTotal)
	}

	klog.Infof("NOTIFY: %s", text)

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
