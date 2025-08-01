package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"regexp"

	"github.com/slack-go/slack"
	"k8s.io/klog/v2"
)

type MessageInput struct {
	Row DecoratedRow
	Via []string
}

func stripCredentialsFromCurl(cmd string) string {
	// look for curl commands and strip credentials if any are found
	if strings.Contains(cmd, "curl") {
		// Bearer tokens
		if strings.Contains(cmd, "Bearer") {
			re := regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)(\S+)`)
			cmd = re.ReplaceAllString(cmd, `${1}<token stripped from output>`)
		}

		// API keys in headers
		if strings.Contains(cmd, "-H") {
			re := regexp.MustCompile(`(?i)(-H\s+["\'][^"']*(?:api[-_]?key|auth|token)[^"']*:\s*)([^"'\s]+)(["\'])`)
			cmd = re.ReplaceAllString(cmd, `${1}<key stripped from output>${3}`)
		}

		// API keys in URL parameters
		if strings.Contains(cmd, "=") {
			re := regexp.MustCompile(`(?i)([\?&][^=]*(?:api[-_]?key|auth|token)[^=]*=)([^&\s"']+)`)
			cmd = re.ReplaceAllString(cmd, `${1}<key stripped from output>`)
		}

		// Basic auth
		if strings.Contains(cmd, "-u") {
			re := regexp.MustCompile(`(?i)(-u\s+)(\S+)`)
			cmd = re.ReplaceAllString(cmd, `${1}<credentials stripped from output>`)
		}
	}
	return cmd
}

func Format(m MessageInput, fancy bool) *slack.Message {
	row := m.Row

	id := row.Decorations["hardware_serial"]
	if row.Decorations["device_owner_email"] != "" {
		id, _, _ = strings.Cut(row.Decorations["device_owner_email"], "@")
	}

	t := time.Unix(row.UNIXTime, 0)
	title := fmt.Sprintf("%s %s — %s @%s %s", scoreToEmoji(row.Score), row.Kind, id, row.Decorations["computer_name"], t.Format(time.TimeOnly))

	var content []*slack.SectionBlock
	kind := "unknown"

	if !fancy {
		klog.V(1).Infof("using plain format for %+v", row.Row)
		kind = "plain"
		content = plainFormat(row.Row, row.VirusTotal)
	} else if row.Row["p0_name"] != "" {
		kind = "tree"
		klog.V(1).Infof("using tree format for %+v", row.Row)
		content = treeFormat(row.Row, row.VirusTotal)
	} else {
		kind = "table"
		klog.V(1).Infof("using table format for %+v", row.Row)
		content = tableFormat(row.Row, row.VirusTotal, false)
	}

	klog.V(1).Infof("%q returned %d content blocks: %v", kind, len(content), content)

	titleBlock := slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, title, false, false))

	var msg slack.Message
	msg = slack.AddBlockMessage(msg, titleBlock)
	for _, c := range content {
		msg = slack.AddBlockMessage(msg, c)
	}
	if row.Interpretation != "" {
		msg = slack.AddBlockMessage(msg, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("AI: %s", row.Interpretation), false, false), nil, nil))
	}

	return &msg
}

func wordWrap(s string, max int, indent int) string {
	// slow, but effective
	var sb strings.Builder
	for i := range s {
		if i > 0 && i%max == 0 && i != len(s) {
			klog.V(1).Infof("wrap %s at %d / %d", s, i, len(s))
			sb.WriteString("\n")
			sb.WriteString(strings.Repeat(" ", indent))
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func treeLine(prefix string, row Row, vr VTRow, level int) string {
	klog.V(1).Infof("treeline row: [[%+v]]", row)

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

	// Strip credentials from curl commands
	cmd = stripCredentialsFromCurl(cmd)
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
	klog.V(1).Infof("env: %s", env)
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

	s := fmt.Sprintf("<%s|%s %s>", v.URL, KindToEmoji[v.Score], name)
	klog.Infof("VT: %s from %+v", s, v)
	return s
}

func treeFormat(row Row, vr VTRow) []*slack.SectionBlock {
	klog.V(1).Infof("tree format row: %s\n\nvt: %+v", row, vr)

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

	klog.V(1).Infof("TREE FORMAT (%d bytes): %s", len(sb.String()), sb.String())
	blocks := []*slack.SectionBlock{slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, sb.String(), false, false), nil, nil)}
	// print extra non-process fields
	blocks = append(blocks, tableFormat(row, vr, true)...)
	return blocks
}

func plainFormat(r Row, vr VTRow) []*slack.SectionBlock {
	klog.V(1).Infof("plain format row: %s\n\nvt: %+v", r, vr)

	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var longText strings.Builder
	var exceptions strings.Builder

	for _, k := range keys {
		v := r[k]

		if strings.TrimSpace(v) == "" {
			continue
		}

		// exception keys are printed last
		if strings.HasSuffix(k, "exception") || strings.HasSuffix(k, "_key") {
			exceptions.WriteString(fmt.Sprintf("*%s*: `%s`\n", k, v))
			continue
		}

		// Strip credentials from command-related fields
		if strings.Contains(k, "cmd") || strings.HasSuffix(k, "cmdline") {
			v = stripCredentialsFromCurl(v)
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

		longText.WriteString(fmt.Sprintf("*%s*: %s\n", k, v))
	}

	blocks := []*slack.SectionBlock{}

	if longText.Len() > 0 {
		blocks = append(blocks, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, longText.String(), false, false), nil, nil))
	}

	if exceptions.Len() > 0 {
		blocks = append(blocks, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, exceptions.String(), false, false), nil, nil))
	}

	return blocks
}

func tableFormat(r Row, vr VTRow, skipProcesses bool) []*slack.SectionBlock {
	klog.V(1).Infof("table format row: %s\n\nvt: %+v", r, vr)

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
		if skipProcesses && (strings.HasPrefix(k, "p0_") || strings.HasPrefix(k, "p1_") || strings.HasPrefix(k, "p2_") || strings.HasPrefix(k, "p3_")) {
			continue
		}

		// empty block, should we care?
		if strings.TrimSpace(v) == "" {
			continue
		}

		// exception keys are printed last
		if strings.HasSuffix(k, "exception") || strings.HasSuffix(k, "_key") {
			exceptions.WriteString(fmt.Sprintf("*%s*: `%s`\n", k, v))
			continue
		}

		// Strip credentials from command-related fields
		if strings.Contains(k, "cmd") || strings.HasSuffix(k, "cmdline") {
			v = stripCredentialsFromCurl(v)
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
