package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		in   MessageInput
		want string
	}{
		{MessageInput{Row: DecoratedRow{Kind: "name", Row: Row{"process": "systemd"}, Decorations: map[string]string{"computer_name": "computer", "device_owner_email": "x@example.com"}}},
			"*name* on computer at 31 Dec 69 19:00 EST (x@):\n> process:systemd"},
		{MessageInput{Row: DecoratedRow{Kind: "tree",
			Row: Row{
				"p0_cgroup":    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-xyz.scope",
				"p0_changed":   "2023-01-31 13:05:47",
				"p0_cmd":       "docker run node tail -f /dev/null",
				"p0_cwd":       "/home/josborne/code/chainguard/chainguard-dev/gke-demo",
				"p0_euid":      "1000",
				"p0_modified":  "2022-12-20 17:15:10",
				"p0_name":      "docker",
				"p0_path":      "/usr/bin/docker",
				"p0_pid":       "644670",
				"p0_runtime_s": "380",
				"p1_cmd":       "/usr/lib/systemd/systemd --user",
				"p1_euid":      "1000",
				"p1_mode":      "0755",
				"p1_name":      "doko",
				"p1_path":      "/usr/lib/systemd/systemd",
				"p1_pid":       "4482",
				"p2_cmd":       "/usr/lib/systemd/systemd rhgb --switched-root --system --deserialize 31",
				"p2_name":      "systemd",
				"p2_path":      "/usr/lib/systemd/systemd",
				"p2_pid":       "1",
			},
			Decorations: map[string]string{"computer_name": "computer", "device_owner_email": "x@example.com"}}},
			`*tree* on computer at 31 Dec 69 19:00 EST (x@):
---
[644670@1000] /usr/bin/docker run node tail -f /dev/null
| cgroup: /user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-xyz.scope
| changed: 2023-01-31 13:05:47
| cwd: /home/josborne/code/chainguard/chainguard-dev/gke-demo
| modified: 2022-12-20 17:15:10
| runtime_s: 380
++ [4482@1000] {doko} /usr/lib/systemd/systemd --user
 | mode: 0755
 ++ [1] /usr/lib/systemd/systemd rhgb --switched-root --system --deserialize 31
---
`},
		{MessageInput{Row: DecoratedRow{Kind: "tree",
			Row: Row{
				"ctime":     "1681810997",
				"mtime":     "1681810945",
				"p0_cgroup": "/user.slice/user-1000.slice/session-3.scope",
				"p0_cmd":    "etcd",
				"p0_cwd":    "/home/eddiezane",
				"p0_euid":   "1000",
				"p0_name":   "etcd",
				"p0_path":   "/usr/bin/etcd",
				"p0_pid":    "91236",
				"p0_sha256": "c30fc288f693a4cd1858df8779d5a888e72ac4fb23c0a1eaf4c4aa6859032a3c",
				"p1_cmd":    "-zsh",
				"p1_euid":   "1000",
				"p1_name":   "zsh",
				"p1_path":   "/usr/bin/zsh",
				"p1_pid":    "78495",
				"p1_sha256": "1d6c2d03b51d9c06cfa33f32533352785f82697650695822e023d22be9cbcc19",
				"p2_cmd":    "tmux",
				"p2_name":   "tmux:server",
				"p2_path":   "/usr/bin/tmux",
				"p2_pid":    "3308",
				"p2_sha256": "aac5656e393dc19a801dfd81f3d333e7c6bf7bd288e74009fbadd851b57f7439",
			},
			VirusTotal: VTRow{
				"p0_sha256": &VTResult{
					URL: "https://www.virustotal.com/gui/file/c30fc288f693a4cd1858df8779d5a888e72ac4fb23c0a1eaf4c4aa6859032a3c",
				},
				"p1_sha256": &VTResult{
					Name:  "zsh",
					URL:   "https://www.virustotal.com/gui/file/1d6c2d03b51d9c06cfa33f32533352785f82697650695822e023d22be9cbcc19",
					Tags:  []string{"64bits", "elf", "shared-lib"},
					Found: true,
					Kind:  Undetected,
				},
				"p2_sha256": &VTResult{
					URL: "https://www.virustotal.com/gui/file/aac5656e393dc19a801dfd81f3d333e7c6bf7bd288e74009fbadd851b57f7439",
				},
			},
			Decorations: map[string]string{"computer_name": "computer", "device_owner_email": "x@example.com"}}},
			`*tree* on computer at 31 Dec 69 19:00 EST (x@):
---
[91236@1000] /usr/bin/etcd
| cgroup: /user.slice/user-1000.slice/session-3.scope
| cwd: /home/eddiezane
| sha256: 👽 [not found](https://www.virustotal.com/gui/file/c30fc288f693a4cd1858df8779d5a888e72ac4fb23c0a1eaf4c4aa6859032a3c)
++ [78495@1000] {zsh} -zsh
 | sha256: 🤷 [zsh](https://www.virustotal.com/gui/file/1d6c2d03b51d9c06cfa33f32533352785f82697650695822e023d22be9cbcc19)
 ++ [3308] {tmux:server} /usr/bin/tmux
  | sha256: 👽 [not found](https://www.virustotal.com/gui/file/aac5656e393dc19a801dfd81f3d333e7c6bf7bd288e74009fbadd851b57f7439)

ctime: 1681810997
mtime: 1681810945
---
`},
	}
	for _, tc := range tests {
		got := Format(tc.in)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Fatalf("expected:\n%v\ngot:\n%v\ndiff:\n%s", tc.want, got, diff)
		}
	}
}

func TestWordWrap(t *testing.T) {
	tests := []struct {
		in     string
		max    int
		indent int
		want   string
	}{
		{"abcdefgh", 4, 2, "abcd\n  efgh"},
	}
	for _, tc := range tests {
		got := wordWrap(tc.in, tc.max, tc.indent)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Fatalf("expected:\n%v\ngot:\n%v\ndiff:\n%s", tc.want, got, diff)
		}
	}
}
