package main

import (
	"fmt"
	"strings"

	"github.com/VirusTotal/vt-go"
	"k8s.io/klog/v2"
)

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
	lines := []string{}

	vo, err := vtCacheGet(c, key)
	if err != nil {
		return "", fmt.Errorf("cache get: %w", err)
	}

	if vo == nil {
		return "not found", nil
	}

	m, err := vo.GetInt64("last_analysis_stats.malicious")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.malicious: %w", err)
	}

	if m > 0 {
		lines = append(lines, fmt.Sprintf("** LIKELY MALICIOUS (%d hits): %s **", m, url))
	}

	s, err := vo.GetInt64("last_analysis_stats.suspicious")
	if err != nil {
		return "", fmt.Errorf("last_analysis_stats.suspicious: %w", err)
	}
	if s > 0 {
		lines = append(lines, fmt.Sprintf("** SUSPICIOUS (%d hits): %s **", s, url))
	}

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

	if len(lines) > 0 {
		lines = append(lines, url)
	}

	return strings.Join(lines, "; "), nil
}

func vtMetadata(r Row, c *vt.Client) (Row, error) {
	vr := Row{}
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
