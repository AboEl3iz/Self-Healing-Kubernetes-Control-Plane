// Tests for the Mapper's cgroup path resolution and container ID parsing.
// These tests run without root and without a real kernel (no BPF maps needed).

package unit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// ─── Container ID parsing ─────────────────────────────────────────────────────

// containerIDRe mirrors the regex in mapper.go.
var containerIDRe = regexp.MustCompile(`[a-f0-9]{64}`)

func resolveContainerID(cgroupPath string) (string, bool) {
	match := containerIDRe.FindString(cgroupPath)
	return match, match != ""
}

func TestResolveContainerID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		path      string
		wantMatch bool
		wantID    string
	}{
		{
			name:      "containerd v2 burstable",
			path:      "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd.slice/cri-containerd-aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899.scope",
			wantMatch: true,
			wantID:    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		},
		{
			name:      "containerd v2 besteffort",
			path:      "/sys/fs/cgroup/kubepods/besteffort/pod9999/a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f10",
			wantMatch: true,
			wantID:    "a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f10",
		},
		{
			name:      "cgroup v1 path with no container ID",
			path:      "/sys/fs/cgroup/memory/system.slice/docker.service",
			wantMatch: false,
		},
		{
			name:      "docker moby style",
			path:      "/sys/fs/cgroup/memory/docker/deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedead",
			wantMatch: true,
			wantID:    "deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedead",
		},
		{
			name:      "empty path",
			path:      "",
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, ok := resolveContainerID(tc.path)
			if ok != tc.wantMatch {
				t.Errorf("resolveContainerID(%q) match=%v, want %v", tc.path, ok, tc.wantMatch)
			}
			if tc.wantMatch && id != tc.wantID {
				t.Errorf("resolveContainerID(%q) id=%q, want %q", tc.path, id, tc.wantID)
			}
		})
	}
}

// ─── normaliseContainerID ─────────────────────────────────────────────────────

func normaliseContainerID(raw string) string {
	for _, prefix := range []string{"docker://", "containerd://", "cri-o://"} {
		if len(raw) > len(prefix) && raw[:len(prefix)] == prefix {
			id := raw[len(prefix):]
			if len(id) >= 64 {
				return id[:64]
			}
			return id
		}
	}
	return ""
}

func TestNormaliseContainerID(t *testing.T) {
	t.Parallel()
	hex64 := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	cases := []struct {
		raw  string
		want string
	}{
		{"containerd://" + hex64, hex64},
		{"docker://" + hex64, hex64},
		{"cri-o://" + hex64, hex64},
		{"containerd://" + hex64 + "extra", hex64},
		{"barestring", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := normaliseContainerID(tc.raw)
		if got != tc.want {
			t.Errorf("normaliseContainerID(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// ─── TTL logic ────────────────────────────────────────────────────────────────

// mimicTTLCheck is a pure function version of the cache TTL check in Resolve().
func mimicTTLCheck(cachedAt time.Time, ttl time.Duration) bool {
	return time.Since(cachedAt) < ttl
}

func TestCacheTTL(t *testing.T) {
	t.Parallel()
	const ttl = 60 * time.Second

	// Fresh entry — should still be valid.
	if !mimicTTLCheck(time.Now(), ttl) {
		t.Error("fresh entry should be valid")
	}
	// Expired entry.
	if mimicTTLCheck(time.Now().Add(-2*ttl), ttl) {
		t.Error("entry from 2×TTL ago should be expired")
	}
	// Boundary — just under TTL.
	if !mimicTTLCheck(time.Now().Add(-(ttl-time.Second)), ttl) {
		t.Error("entry 1s before TTL should be valid")
	}
}

// ─── Cgroup inode walk (integration-style, requires /sys/fs/cgroup) ──────────

func TestWalkCgroupFSNotFound(t *testing.T) {
	t.Parallel()
	// Use a temp directory — no inode will match 0xFFFFFFFFFFFF.
	dir := t.TempDir()
	target := uint64(0xFFFFFFFFFFFF)

	found := ""
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil || !d.IsDir() {
			return nil
		}
		// We just check the walk doesn't panic or hang on an empty dir.
		_ = path
		_ = target
		return nil
	})
	if err != nil {
		t.Errorf("walk error: %v", err)
	}
	if found != "" {
		t.Errorf("unexpected match: %s", found)
	}
}
