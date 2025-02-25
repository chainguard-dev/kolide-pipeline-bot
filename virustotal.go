package main

import (
	"fmt"
	"strings"

	"github.com/VirusTotal/vt-go"
	"k8s.io/klog/v2"
)

type VTResult struct {
	URL   string
	Found bool
	Tags  []string

	KnownHash bool
	Name      string
	Vendor    string

	Reputation int64

	MaliciousVotes  int
	SuspiciousVotes int
	HarmlessVotes   int
	UndetectedVotes int

	Country string

	Verdict string
	Score   Kind

	Raw *vt.Object
}

type Kind int

const (
	NoInformationAvailable Kind = iota
	HarmlessKnown
	Harmless
	NoOpinion
	PossiblySuspicious
	Suspicious
	PossiblyMalicious
	Malicious
)

var KindToEmoji = map[Kind]string{
	NoInformationAvailable: "🤷",
	HarmlessKnown:          "✅",
	Harmless:               "🟢",
	NoOpinion:              "🔵",
	PossiblySuspicious:     "🟡",
	Suspicious:             "🟠",
	PossiblyMalicious:      "🔴",
	Malicious:              "👹",
}

var KindToString = map[Kind]string{
	NoInformationAvailable: "no_information_available",
	HarmlessKnown:          "harmless_and_known",
	Harmless:               "harmless",
	NoOpinion:              "undetected_no_opinion",
	PossiblySuspicious:     "possibly_suspicious",
	Suspicious:             "suspicious",
	PossiblyMalicious:      "possibly_malicious",
	Malicious:              "malicious",
}

type VTRow map[string]*VTResult

var vtDumbCache = map[string]*vt.Object{}

func vtCacheGet(c *vt.Client, key string) (*vt.Object, error) {
	if strings.HasSuffix(key, "/") {
		klog.Warningf("asked to fetch impartial key: %s", key)
		return nil, nil
	}

	if v := vtDumbCache[key]; v != nil {
		klog.V(1).Infof("cached[%v]: %+v", key, v)
		return v, nil
	}

	v, err := c.GetObject(vt.URL(key))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			klog.V(1).Infof("%s not found", key)
			return v, nil
		}

		return nil, fmt.Errorf("get object: %w", err)
	}
	klog.V(1).Infof("uncached[%v]: %+v", key, v)

	vtDumbCache[key] = v
	return v, nil
}

func vtInterpret(c *vt.Client, key string) (*VTResult, error) {
	if strings.HasPrefix(key, "/") {
		klog.Warningf("passed weird key: %s", key)
		return nil, nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/gui/%s", strings.Replace(key, "files", "file", 1))
	url = strings.Replace(url, "ip_addresses", "ip-address", 1)

	r := &VTResult{
		URL:     url,
		Score:   NoInformationAvailable,
		Verdict: KindToString[NoInformationAvailable],
	}

	vo, err := vtCacheGet(c, key)
	if err != nil {
		return nil, fmt.Errorf("cache get: %w", err)
	}

	if vo == nil {
		return r, nil
	}
	r.Raw = vo
	r.Found = true

	ss, err := vo.GetStringSlice("tags")
	if err != nil {
		return nil, fmt.Errorf("tags: %w", err)
	}
	r.Tags = ss

	s, err := vo.GetString("meaningful_name")
	if err == nil {
		r.Name = s
	}

	ss, err = vo.GetStringSlice("names")
	if err == nil && len(ss) > 0 && r.Name == "" {
		r.Name = ss[0]
	}

	ss, err = vo.GetStringSlice("known_distributors.distributors")
	if err == nil && len(ss) > 0 {
		r.Vendor = ss[0]
	}

	reputation, err := vo.GetInt64("reputation")
	if err != nil {
		return nil, fmt.Errorf("reputation: %w", err)
	}
	r.Reputation = reputation

	harmless, err := vo.GetInt64("last_analysis_stats.harmless")
	if err != nil {
		return nil, fmt.Errorf("last_analysis_stats.harmless: %w", err)
	}
	r.HarmlessVotes = int(harmless)

	undetected, err := vo.GetInt64("last_analysis_stats.undetected")
	if err != nil {
		return nil, fmt.Errorf("last_analysis_stats.undetected: %w", err)
	}
	r.UndetectedVotes = int(undetected)

	malicious, err := vo.GetInt64("last_analysis_stats.malicious")
	if err != nil {
		return nil, fmt.Errorf("last_analysis_stats.malicious: %w", err)
	}
	r.MaliciousVotes = int(malicious)

	suspicious, err := vo.GetInt64("last_analysis_stats.suspicious")
	if err != nil {
		return nil, fmt.Errorf("last_analysis_stats.suspicious: %w", err)
	}
	r.SuspiciousVotes = int(suspicious)

	klog.Infof("%s reputation: %d [harmless=%d, undetected=%d, malicious=%d, suspicious=%d]", key, reputation, harmless, undetected, malicious, suspicious)

	switch {
	case malicious > 2:
		r.Score = Malicious
	case malicious > 1:
		r.Score = PossiblyMalicious
	case suspicious > 2:
		r.Score = Suspicious
	case suspicious > 1:
		r.Score = PossiblySuspicious
	case harmless > 3:
		r.Score = Harmless
	case undetected > 1:
		r.Score = NoOpinion
	}

	// Upgrade known
	if r.Vendor != "" && r.Score < Suspicious {
		r.Score = HarmlessKnown
	}

	// Downgrade items with a poor reputation
	if r.Reputation < 0 && r.Score < Suspicious {
		klog.Infof("downgrading to possibly suspicious due to poor reputation: %d", r.Reputation)
		r.Score = PossiblySuspicious
	}
	if r.Reputation < -2 && r.Score < Suspicious {
		klog.Infof("downgrading to suspicious due to poor reputation: %d", r.Reputation)
		r.Score = Suspicious
	}

	as, err := vo.GetString("as_owner")
	if err != nil {
		klog.V(1).Infof("as_owner: %v", err)
	}

	if as != "" && r.Vendor == "" {
		r.Vendor = as
	}

	co, err := vo.GetString("country")
	if err != nil {
		klog.V(1).Infof("country: %v", err)
	}
	if co != "" {
		r.Vendor = fmt.Sprintf("%s [%s]", r.Vendor, r.Country)
		r.Country = co
	}

	sub, err := vo.GetStringSlice("last_https_certificate.extensions.subject_alternative_name")
	if err != nil {
		klog.Errorf("last_https_certificate.subject: %v", err)
	}
	if len(sub) > 0 && r.Name == "" {
		r.Name = strings.Join(sub, ",")
	}

	r.Verdict = KindToString[r.Score]
	return r, nil
}

func vtMetadata(r Row, c *vt.Client) (VTRow, error) {
	vr := VTRow{}
	if c == nil {
		return vr, nil
	}

	for k, v := range r {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if strings.Contains(k, "sha256") || strings.HasSuffix(k, "_hash") {
			vs, err := vtInterpret(c, fmt.Sprintf("files/%s", v))
			if err != nil {
				return vr, fmt.Errorf("get object: %w", err)
			}
			vr[k] = vs
			klog.V(1).Infof("VT[%s]: %s", k, vs)
		}

		if strings.Contains(k, "remote_address") {
			vs, err := vtInterpret(c, fmt.Sprintf("ip_addresses/%s", v))
			if err != nil {
				return vr, fmt.Errorf("get object: %w", err)
			}
			vr[k] = vs
			klog.V(1).Infof("VT[%s]: %s", k, vs)
		}
	}

	return vr, nil
}
