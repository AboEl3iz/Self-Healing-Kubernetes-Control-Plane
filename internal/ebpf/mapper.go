// Package ebpf — mapper.go resolves kernel cgroup IDs to Kubernetes pod metadata.
//
// Resolution chain:
//
//	cgroup_id (from BPF map key)
//	  → walk /sys/fs/cgroup to find dir by inode == cgroup_id  (cgroup v2)
//	  → parse container ID (64-hex) from the kubepods path segment
//	  → Kubernetes Informer cache: containerID → PodInfo
//	  → return PodInfo{PodName, Namespace, Deployment, Container, NodeName}
//	  → cache in sync.Map with 60s TTL
//	  → On pod DELETE: invalidate cache entry
//
// cgroup v1 fallback: if /sys/fs/cgroup/<path> inode walk fails,
// we try /sys/fs/cgroup/memory/<path> (cgroup v1 memory hierarchy).
//
// Performance target: <1ms for cache hits, <50ms for misses.

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// PodInfo holds the resolved Kubernetes identity for a cgroup_id.
type PodInfo struct {
	PodName    string
	Namespace  string
	Deployment string // owner Deployment or StatefulSet (may be empty)
	Container  string // container name within the pod
	NodeName   string
	CachedAt   time.Time // for TTL eviction
}

// CacheTTL is how long a resolved PodInfo entry is kept.
const CacheTTL = 60 * time.Second

// containerIDRe matches 64-hex container IDs in kubepods cgroup paths.
// Handles containerd, docker, and cri-o path formats:
//
//	kubepods/burstable/pod<uid>/<64-hex>
//	kubepods.burstable/pod<uid>/<64-hex>   (systemd slice syntax)
var containerIDRe = regexp.MustCompile(`[a-f0-9]{64}`)

// Mapper resolves cgroup IDs to Kubernetes pod metadata.
type Mapper struct {
	nodeName string
	logger   *slog.Logger

	// podCache: map[uint64 cgroup_id]*PodInfo
	podCache sync.Map

	// containerIndex: map[containerID string]*PodInfo built from K8s informer
	containerIndex sync.Map

	// cgroupPathCache: map[uint64 cgroup_id]string — inode→path cache
	cgroupPathCache sync.Map
}

// NewMapper creates a new Mapper. Call Start() to begin watching pod events.
func NewMapper(nodeName string, logger *slog.Logger) *Mapper {
	return &Mapper{
		nodeName: nodeName,
		logger:   logger,
	}
}

// Start begins the Kubernetes Informer watch loop for pod lifecycle events.
// This populates containerIndex so that Resolve() can map container IDs to pods.
// Blocks until ctx is cancelled.
func (m *Mapper) Start(ctx context.Context) error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("mapper: in-cluster config failed: %w", err)
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("mapper: k8s client failed: %w", err)
	}

	// Watch only pods on this node to minimise informer overhead.
	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", m.nodeName).String()

	// Create a filtered pod ListWatcher scoped to this node.
	podInformer := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"pods",
		corev1.NamespaceAll,
		fields.ParseSelectorOrDie(fieldSelector),
	)

	store, controller := cache.NewInformer(
		podInformer,
		&corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { m.onPodAdd(obj) },
			UpdateFunc: func(_, obj interface{}) { m.onPodAdd(obj) },
			DeleteFunc: func(obj interface{}) { m.onPodDelete(obj) },
		},
	)
	_ = store

	m.logger.Info("mapper: starting Kubernetes pod informer", "node", m.nodeName)
	go controller.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), controller.HasSynced) {
		return fmt.Errorf("mapper: informer cache sync timed out")
	}
	m.logger.Info("mapper: pod cache synced")

	<-ctx.Done()
	return ctx.Err()
}

// onPodAdd indexes every container ID in the pod → PodInfo.
func (m *Mapper) onPodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	deployment := ownerName(pod)
	for _, cs := range pod.Status.ContainerStatuses {
		containerID := normaliseContainerID(cs.ContainerID)
		if containerID == "" {
			continue
		}
		info := &PodInfo{
			PodName:    pod.Name,
			Namespace:  pod.Namespace,
			Deployment: deployment,
			Container:  cs.Name,
			NodeName:   pod.Spec.NodeName,
			CachedAt:   time.Now(),
		}
		m.containerIndex.Store(containerID, info)
		m.logger.Debug("mapper: indexed container", "container_id", containerID[:12], "pod", pod.Name)
	}
}

// onPodDelete removes all container ID entries for the deleted pod.
func (m *Mapper) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		containerID := normaliseContainerID(cs.ContainerID)
		if containerID != "" {
			m.containerIndex.Delete(containerID)
		}
	}
	// Evict all cgroup_id cache entries pointing to this pod.
	m.podCache.Range(func(k, v any) bool {
		if info, ok := v.(*PodInfo); ok && info.PodName == pod.Name && info.Namespace == pod.Namespace {
			m.podCache.Delete(k)
		}
		return true
	})
	m.logger.Debug("mapper: evicted pod", "pod", pod.Name)
}

// Resolve returns the PodInfo for a given cgroup_id.
// Fast path: cache hit. Slow path: cgroup walk + container index lookup.
func (m *Mapper) Resolve(cgroupID uint64) (*PodInfo, error) {
	// Fast path
	if v, ok := m.podCache.Load(cgroupID); ok {
		info := v.(*PodInfo)
		if time.Since(info.CachedAt) < CacheTTL {
			return info, nil
		}
		m.podCache.Delete(cgroupID)
	}

	// Slow path: walk cgroup fs to get the path
	cgroupPath, err := m.resolveCgroupPath(cgroupID)
	if err != nil {
		return nil, fmt.Errorf("mapper: cgroup %d: %w", cgroupID, err)
	}

	containerID, err := m.resolveContainerID(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("mapper: cgroup path %q: %w", cgroupPath, err)
	}

	v, ok := m.containerIndex.Load(containerID)
	if !ok {
		return nil, fmt.Errorf("mapper: container %s not in index (pod not yet seen?)", containerID[:12])
	}
	info := v.(*PodInfo)
	info.CachedAt = time.Now()
	m.podCache.Store(cgroupID, info)
	return info, nil
}

// Invalidate removes a cgroup_id from the hot cache. Called externally if needed.
func (m *Mapper) Invalidate(cgroupID uint64) {
	m.podCache.Delete(cgroupID)
	m.cgroupPathCache.Delete(cgroupID)
	m.logger.Debug("mapper: cache invalidated", "cgroup_id", cgroupID)
}

// resolveCgroupPath walks /sys/fs/cgroup to find the directory whose inode
// matches cgroupID (cgroup v2 uses inode as the cgroup ID).
// Falls back to /sys/fs/cgroup/memory for cgroup v1.
func (m *Mapper) resolveCgroupPath(cgroupID uint64) (string, error) {
	// Check the path cache first.
	if v, ok := m.cgroupPathCache.Load(cgroupID); ok {
		return v.(string), nil
	}

	roots := []string{"/sys/fs/cgroup", "/sys/fs/cgroup/memory"}
	for _, root := range roots {
		path, err := walkCgroupFS(root, cgroupID)
		if err == nil {
			m.cgroupPathCache.Store(cgroupID, path)
			return path, nil
		}
	}
	return "", fmt.Errorf("inode %d not found under cgroup fs", cgroupID)
}

// walkCgroupFS does a depth-first walk under root looking for a directory
// whose inode number equals target.
func walkCgroupFS(root string, target uint64) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable dirs
		}
		if !d.IsDir() {
			return nil
		}
		var stat syscall.Stat_t
		if e := syscall.Stat(path, &stat); e != nil {
			return nil
		}
		if stat.Ino == target {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && found == "" {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("not found")
	}
	return found, nil
}

// resolveContainerID extracts the container ID from a kubepods cgroup path.
// Supports containerd, docker (moby), and cri-o path styles.
func (m *Mapper) resolveContainerID(cgroupPath string) (string, error) {
	// Normalise systemd slice syntax (- → /) and strip leading "cri-containerd-" etc.
	// The 64-hex segment is the container runtime container ID.
	match := containerIDRe.FindString(cgroupPath)
	if match == "" {
		return "", fmt.Errorf("no 64-hex container ID in cgroup path %q", cgroupPath)
	}
	return match, nil
}

// ownerName extracts the top-level owner (Deployment / StatefulSet / DaemonSet) name.
func ownerName(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		switch ref.Kind {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
			// For ReplicaSets, strip the hash suffix to get the Deployment name.
			name := ref.Name
			if ref.Kind == "ReplicaSet" {
				if idx := strings.LastIndex(name, "-"); idx > 0 {
					name = name[:idx]
				}
			}
			return name
		}
	}
	return ""
}

// normaliseContainerID strips runtime prefixes like "docker://", "containerd://", "cri-o://".
func normaliseContainerID(raw string) string {
	for _, prefix := range []string{"docker://", "containerd://", "cri-o://"} {
		if strings.HasPrefix(raw, prefix) {
			id := strings.TrimPrefix(raw, prefix)
			// Use only the 64-hex ID portion (some runtimes append extra chars).
			if len(id) >= 64 {
				return id[:64]
			}
			return id
		}
	}
	// Already bare or unknown format — no container ID extractable.
	return ""
}
