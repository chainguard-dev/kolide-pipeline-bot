package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/mergestat/timediff"
	"github.com/multiplay/go-slack/chat"
	"github.com/multiplay/go-slack/webhook"
	"k8s.io/klog/v2"
)

func notify(url string, row DecoratedRow) error {
	t := time.Unix(row.UNIXTime, 0)
	diff := strings.Replace(timediff.TimeDiff(t), " ago", " delay", 1)
	text := fmt.Sprintf("*%s* on %s at %s (%s):\n> %s", row.Kind, row.Decorations["computer_name"], t.Format(time.RFC822), diff, row.Row)
	if len(row.VirusTotal) > 0 {
		text = text + "\n\n" + row.VirusTotal.String()
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
