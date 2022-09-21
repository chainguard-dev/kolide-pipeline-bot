package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/VirusTotal/vt-go"
	"k8s.io/klog/v2"
)

type VTRow map[string]string

func (r VTRow) String() string {
	var sb strings.Builder
	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := r[k]
		if len(v) > 384 {
			v = v[0:384] + "..."
		}
		sb.WriteString(fmt.Sprintf("> VT.%s: %s\n", k, v))
	}

	return strings.TrimSpace(sb.String())
}

var vtDumbCache = map[string]*vt.Object{}

func vtCacheGet(c *vt.Client, key string) (*vt.Object, error) {
	if strings.HasSuffix(key, "/") {
		klog.Warningf("asked to fetch impartial key: %s", key)
		return nil, nil
	}

	if v := vtDumbCache[key]; v != nil {
		klog.Infof("cached[%v]: %+v", key, v)
		return v, nil
	}

	v, err := c.GetObject(vt.URL(key))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			klog.Infof("%s not found", key)
			return v, nil
		}

		return nil, fmt.Errorf("get object: %w", err)
	}
	klog.Infof("uncached[%v]: %+v", key, v)

	vtDumbCache[key] = v
	return v, nil
}

func vtInterpret(c *vt.Client, key string) (string, error) {
	if strings.HasPrefix(key, "/") {
		return "", nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/gui/%s", strings.Replace(key, "files", "file", 1))
	url = strings.Replace(url, "ip_addresses", "ip-address", 1)
	lines := []string{}

	vo, err := vtCacheGet(c, key)
	if err != nil {
		return "", fmt.Errorf("cache get: %w", err)
	}

	if vo == nil {
		return "not found", nil
	}

	h, err := vo.GetInt64("last_analysis_stats.harmless")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.harmless: %w", err)
	}

	u, err := vo.GetInt64("last_analysis_stats.undetected")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.undetected: %w", err)
	}

	m, err := vo.GetInt64("last_analysis_stats.malicious")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.malicious: %w", err)
	}

	s, err := vo.GetInt64("last_analysis_stats.suspicious")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.suspicious: %w", err)
	}

	switch {
	case m > 3:
		lines = append(lines, fmt.Sprintf("*MALICIOUS* (%d hits)*: %s", m, url))
	case m > 1:
		lines = append(lines, fmt.Sprintf("*Possibly malicious* (%d hits)*: %s", m, url))
	case s > 1:
		lines = append(lines, fmt.Sprintf("*Possibly suspicious* (%d hits)*: %s", s, url))
	case h > 3:
		lines = append(lines, fmt.Sprintf("Harmless (%d hits): %s", h, url))
	case u > 1:
		lines = append(lines, fmt.Sprintf("Undetected (%d hits): %s", u, url))
	default:
		lines = append(lines, fmt.Sprintf("Unknown: %s", url))
	}

	attr, err := vo.Get("attributes")
	if err != nil {
		klog.Errorf("attributes: %v", err)
	}
	klog.Infof("ATTR: %+v", attr)

	as, err := vo.GetString("attributes.as_owner")
	if err == nil {
		klog.Errorf("attributes.as_owner: %v", err)
	}
	if as != "" {
		lines = append(lines, fmt.Sprintf("AS: %s", as))
	}

	co, err := vo.GetString("attributes.country")
	if err == nil {
		klog.Errorf("attributes.country: %v", err)
	}

	if co != "" {
		lines = append(lines, fmt.Sprintf("Country: %s", co))
	}

	sub, err := vo.GetString("last_https_certificate.subject")
	if err == nil {
		klog.Errorf("last_https_certificate.subject: %v", err)
	}
	if sub != "" {
		lines = append(lines, fmt.Sprintf("Cert: %s", sub))
	}

	if co != "" {
		lines = append(lines, fmt.Sprintf("Country: %s", co))
	}

	tags, err := vo.GetStringSlice("tags")
	if err != nil {
		return "", fmt.Errorf("tags: %w", err)
	}

	if tags != nil {
		lines = append(lines, fmt.Sprintf("tags: %s", strings.Join(tags, " ")))
	}

	return strings.Join(lines, "; "), nil
}

func vtMetadata(r Row, c *vt.Client) (VTRow, error) {
	vr := VTRow{}
	if c == nil {
		return vr, nil
	}

	for k, v := range r {
		if strings.Contains(k, "sha256") {
			vs, err := vtInterpret(c, fmt.Sprintf("files/%s", v))
			if err != nil {
				return vr, fmt.Errorf("get object: %w", err)
			}
			vr[k] = vs
			klog.Infof("VT[%s]: %s", k, vs)
		}

		if strings.Contains(k, "remote_address") {
			vs, err := vtInterpret(c, fmt.Sprintf("ip_addresses/%s", v))
			if err != nil {
				return vr, fmt.Errorf("get object: %w", err)
			}
			vr[k] = vs
			klog.Infof("VT[%s]: %s", k, vs)
		}
	}

	return vr, nil
}
