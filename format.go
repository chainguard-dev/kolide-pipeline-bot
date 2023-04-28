package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"k8s.io/klog/v2"
)

type MessageInput struct {
	Row DecoratedRow
	Via []string
}

func Format(m MessageInput) *slack.Message {
	row := m.Row

	id := row.Decorations["hardware_serial"]
	if row.Decorations["device_owner_email"] != "" {
		id, _, _ = strings.Cut(row.Decorations["device_owner_email"], "@")
	}

	t := time.Unix(row.UNIXTime, 0)
	title := fmt.Sprintf("%s — %s @%s %s", row.Kind, id, row.Decorations["computer_name"], t.Format(time.TimeOnly))

	var content []*slack.SectionBlock

	if row.Row["p0_name"] != "" && row.Row["p1_name"] != "" {
		content = treeFormat(row.Row, row.VirusTotal)
	} else {
		content = genericFormat(row.Row, row.VirusTotal)
	}

	extra := ""
	if len(m.Via) > 0 && len(m.Via) < 5 {
		extra = fmt.Sprintf("\n\nrelated via %s", strings.Join(m.Via, " "))
	}

	titleBlock := slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, title, false, false))
	extraBlock := slack.NewContextBlock("", slack.NewTextBlockObject(slack.MarkdownType, extra, false, false), nil, nil)

	var msg slack.Message
	msg = slack.AddBlockMessage(msg, titleBlock)
	for _, c := range content {
		msg = slack.AddBlockMessage(msg, c)
	}
	if extra != "" {
		msg = slack.AddBlockMessage(msg, extraBlock)
	}
	return &msg
}

func wordWrap(s string, max int, indent int) string {
	// slow, but effective
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && i%max == 0 && i != len(s) {
			klog.Infof("wrap %s at %d / %d", s, i, len(s))
			sb.WriteString("\n")
			sb.WriteString(strings.Repeat(" ", indent))
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func treeLine(prefix string, row Row, vr VTRow, level int) string {
	klog.Infof("treeline row: [[%+v]]", row)

	uid := row[fmt.Sprintf("%suid", prefix)]
	euid := row[fmt.Sprintf("%seuid", prefix)]
	pid := row[fmt.Sprintf("%spid", prefix)]
	name := row[fmt.Sprintf("%sname", prefix)]
	cmd := row[fmt.Sprintf("%scmd", prefix)]
	path := row[fmt.Sprintf("%spath", prefix)]
	if cmd == "" {
		cmd = row[fmt.Sprintf("%scmdline", prefix)]
	}

	if len(cmd) > 384 {
		cmd = cmd[0:384] + "..."
	}

	// If command-line contains a base version of the path, insert the path.
	cparts := strings.Split(cmd, " ")
	if path != "" && cparts[0] == filepath.Base(path) {
		cmd = strings.Replace(cmd, cparts[0], path, 1)
	}

	// If command-line does not contain the name, prepend it to the line
	if name != "" && filepath.Base(cparts[0]) != name {
		cmd = fmt.Sprintf("{%s} %s", name, cmd)
	}

	env := fmt.Sprintf("pid: %s", pid)
	if euid != "" && pid != "" {
		env = fmt.Sprintf("pid: %s [@%s]", pid, euid)
	}

	if uid != "" && euid != "" && pid != "" && euid != uid {
		env = fmt.Sprintf("pid: %s [@%s from %s]", pid, euid, uid)
	}

	var sb strings.Builder
	if level > 0 {
		if level > 1 {
			sb.WriteString(strings.Repeat(" ", level-1))
		}
		sb.WriteString("▶ ")
	}
	sb.WriteString(fmt.Sprintf("%s\n", wordWrap(cmd, 78-level, level+2)))
	sb.WriteString(strings.Repeat(" ", level))
	klog.Infof("env: %s", env)
	sb.WriteString(fmt.Sprintf("┃ %s\n", env))

	keys := []string{}
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := row[k]
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		// in env
		if strings.HasSuffix(k, "_pid") || strings.HasSuffix(k, "_uid") || strings.HasSuffix(k, "_euid") {
			continue
		}

		if strings.HasSuffix(k, "_name") || strings.HasSuffix(k, "_cmd") || strings.HasSuffix(k, "_cmdline") || strings.HasSuffix(k, "_path") {
			continue
		}

		if vr[k] != nil {
			v = formatVirusTotal(vr[k])
		}

		sb.WriteString(strings.Repeat(" ", level))
		sb.WriteString(fmt.Sprintf("┃ %s: %s\n", strings.ReplaceAll(k, prefix, ""), v))
	}

	return sb.String()
}

func formatVirusTotal(v *VTResult) string {
	name := "unknown"
	if !v.Found {
		name = "missing"
	}
	if v.Vendor != "" {
		name = fmt.Sprintf("%s:%s", v.Name, strings.ToLower(v.Vendor))
	}

	if v.Name != "" && v.Vendor == "" {
		name = v.Name
	}

	if len(name) > 78 {
		name = name[0:76] + "..."
	}

	s := fmt.Sprintf("<%s|%s %s>", v.URL, KindToEmoji[v.Kind], name)
	klog.Infof("VT: %s from %+v", s, v)
	return s
}

func treeFormat(row Row, vr VTRow) []*slack.SectionBlock {
	klog.Infof("tree format row: %s\n\nvt: %+v", row, vr)

	var sb strings.Builder
	sb.WriteString("```")
	if row["p0_path"] != "" || row["p0_name"] != "" {
		sb.WriteString(treeLine("p0_", row, vr, 0))
	}
	if row["p1_path"] != "" || row["p1_name"] != "" {
		sb.WriteString(treeLine("p1_", row, vr, 1))
	}
	if row["p2_path"] != "" || row["p2_name"] != "" {
		sb.WriteString(treeLine("p2_", row, vr, 2))
	}
	if row["p3_path"] != "" || row["p3_name"] != "" {
		sb.WriteString(treeLine("p3_", row, vr, 3))
	}

	sb.WriteString("```")
	blocks := []*slack.SectionBlock{slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, sb.String(), false, false), nil, nil)}
	// print extra fields
	blocks = append(blocks, genericFormat(row, vr)...)
	return blocks
}

func genericFormat(r Row, vr VTRow) []*slack.SectionBlock {
	klog.Infof("generic format row: %s\n\nvt: %+v", r, vr)

	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fields := []*slack.TextBlockObject{}
	var longText strings.Builder
	var exceptions strings.Builder

	for _, k := range keys {
		v := r[k]

		// handled by treeFormat
		if strings.HasPrefix(k, "p0_") || strings.HasPrefix(k, "p1_") || strings.HasPrefix(k, "p2_") || strings.HasPrefix(k, "p3_") {
			continue
		}

		// empty block, should we care?
		if strings.TrimSpace(v) == "" {
			continue
		}

		// exception keys are printed last
		if strings.HasSuffix(k, "exception") || strings.HasSuffix(k, "_key") {
			exceptions.WriteString(fmt.Sprintf("*%s*: `%s`", k, v))
			continue
		}

		if len(v) > 768 {
			v = v[0:768] + "..."
		}

		if vr[k] != nil {
			v = formatVirusTotal(vr[k])
		} else {
			if len(v) > 96 || !strings.Contains(v, " ") || strings.HasPrefix(v, "/") {
				v = fmt.Sprintf("`%s`", v)
			}
		}

		if len(k+v) > 80 {
			longText.WriteString(fmt.Sprintf("*%s*: %s\n", k, v))
			continue
		}

		fields = append(fields, slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*%s*: %s", k, v), false, false))
	}

	blocks := []*slack.SectionBlock{}

	if longText.Len() > 0 {
		blocks = append(blocks, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, longText.String(), false, false), nil, nil))
	}

	// Slack has a maximum number of fields in a block :(
	bfields := []*slack.TextBlockObject{}
	for i, b := range fields {
		bfields = append(bfields, b)
		if i > 0 && i%9 == 0 {
			blocks = append(blocks, slack.NewSectionBlock(nil, bfields, nil))
			bfields = []*slack.TextBlockObject{}
		}
	}

	if len(bfields) > 0 {
		blocks = append(blocks, slack.NewSectionBlock(nil, bfields, nil))
	}

	if exceptions.Len() > 0 {
		blocks = append(blocks, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, exceptions.String(), false, false), nil, nil))
	}
	return blocks
}
