// Package intelligence — graph.go implements the Kubernetes resource dependency
// graph used by the causal reasoning engine.
//
// The graph captures the physical and logical relationships between K8s resources:
//
//	Node
//	 ├── Pod A  ──owns──► PVC ──binds──► PersistentVolume ──uses──► disk device
//	 ├── Pod B
//	 └── Pod C  ──uses──► Network (node-level NIC/bridge)
//
// At startup the graph is populated from the Kubernetes API (Node + Pod + PVC
// informers). It is then kept live via an optional Watch loop.
//
// Thread safety: all read/write operations are protected by a sync.RWMutex.
// Callers MUST NOT mutate the returned slices.

package intelligence

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ResourceKind identifies the type of Kubernetes resource.
type ResourceKind string

const (
	KindPod     ResourceKind = "Pod"
	KindNode    ResourceKind = "Node"
	KindVolume  ResourceKind = "PersistentVolume"
	KindNetwork ResourceKind = "Network"
)

// EdgeRelation describes the semantic of an edge between two resources.
type EdgeRelation string

const (
	RelRunsOn  EdgeRelation = "runs_on"  // Pod → Node
	RelUsesPVC EdgeRelation = "uses_pvc" // Pod → Volume
	RelUsesNet EdgeRelation = "uses_net" // Pod → Network
)

// ResourceNode represents a single vertex in the dependency graph.
type ResourceNode struct {
	ID        string // unique: kind/namespace/name (or kind/name for cluster-scoped)
	Kind      ResourceKind
	Name      string
	Namespace string
	Labels    map[string]string
}

// resourceID builds a canonical, unique ID string for a resource.
func resourceID(kind ResourceKind, namespace, name string) string {
	if namespace == "" {
		return fmt.Sprintf("%s/%s", kind, name)
	}
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

// Edge represents a directed relationship between two resources.
type Edge struct {
	From     string // ResourceNode.ID
	To       string // ResourceNode.ID
	Relation EdgeRelation
}

// DependencyGraph holds the full resource dependency graph.
// All exported methods are safe for concurrent use.
type DependencyGraph struct {
	mu    sync.RWMutex
	nodes map[string]*ResourceNode // id → node
	edges []Edge
	// pod → node reverse index (fast lookup for aggregator)
	podToNode map[string]string // podID → nodeID
	// node → pod set
	nodeToPods map[string][]string // nodeID → []podID
}

// NewDependencyGraph returns an empty DependencyGraph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes:      make(map[string]*ResourceNode),
		podToNode:  make(map[string]string),
		nodeToPods: make(map[string][]string),
	}
}

// AddNode inserts or replaces a ResourceNode.
func (g *DependencyGraph) AddNode(n ResourceNode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = &n
}

// AddEdge adds a directed edge between two nodes.
// The nodes need not be in the graph yet — they will be resolved at query time.
func (g *DependencyGraph) AddEdge(from, to string, rel EdgeRelation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, Edge{From: from, To: to, Relation: rel})
	if rel == RelRunsOn {
		// Maintain fast reverse indices.
		g.podToNode[from] = to
		g.nodeToPods[to] = appendUnique(g.nodeToPods[to], from)
	}
}

// NodeForPod resolves the node ID that a pod runs on.
// Returns ("", false) if the pod is not in the graph.
func (g *DependencyGraph) NodeForPod(podID string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nid, ok := g.podToNode[podID]
	return nid, ok
}

// PeersOnNode returns all pod IDs that are co-located on the given node.
func (g *DependencyGraph) PeersOnNode(nodeID string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	pods := g.nodeToPods[nodeID]
	if pods == nil {
		return nil
	}
	result := make([]string, len(pods))
	copy(result, pods)
	return result
}

// NodeOf returns the ResourceNode for a given ID.
func (g *DependencyGraph) NodeOf(id string) (*ResourceNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// VolumesForPod returns all PersistentVolume IDs used by the pod.
func (g *DependencyGraph) VolumesForPod(podID string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var volumes []string
	for _, e := range g.edges {
		if e.From == podID && e.Relation == RelUsesPVC {
			volumes = append(volumes, e.To)
		}
	}
	return volumes
}

// SharedVolumes returns the set of volume IDs shared by all given pod IDs.
// Used by the reasoner to confirm a shared-disk root cause.
func (g *DependencyGraph) SharedVolumes(podIDs []string) []string {
	if len(podIDs) == 0 {
		return nil
	}
	// Build volume sets per pod.
	sets := make([]map[string]struct{}, len(podIDs))
	for i, pid := range podIDs {
		sets[i] = make(map[string]struct{})
		for _, v := range g.VolumesForPod(pid) {
			sets[i][v] = struct{}{}
		}
	}
	// Intersect all sets.
	shared := sets[0]
	for _, s := range sets[1:] {
		for v := range shared {
			if _, ok := s[v]; !ok {
				delete(shared, v)
			}
		}
	}
	result := make([]string, 0, len(shared))
	for v := range shared {
		result = append(result, v)
	}
	return result
}

// ─── Kubernetes Informer Sync ─────────────────────────────────────────────────

// SyncFromCluster populates the graph from the live cluster state.
// Call once at startup; re-call on cache invalidation or SIGHUP.
func (g *DependencyGraph) SyncFromCluster(ctx context.Context, client kubernetes.Interface, logger *slog.Logger) error {
	logger.Info("intelligence: syncing dependency graph from cluster")

	// Sync Nodes.
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("graph: list nodes: %w", err)
	}
	for _, n := range nodes.Items {
		id := resourceID(KindNode, "", n.Name)
		g.AddNode(ResourceNode{
			ID:     id,
			Kind:   KindNode,
			Name:   n.Name,
			Labels: n.Labels,
		})
	}

	// Sync Pods across all namespaces.
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("graph: list pods: %w", err)
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == "" {
			continue // unscheduled — skip
		}
		g.addPod(client, ctx, p, logger)
	}

	logger.Info("intelligence: dependency graph populated",
		"nodes", len(nodes.Items),
		"pods", len(pods.Items),
	)
	return nil
}

// addPod adds a single pod and its edges to the graph.
func (g *DependencyGraph) addPod(client kubernetes.Interface, ctx context.Context, p corev1.Pod, logger *slog.Logger) {
	podID := resourceID(KindPod, p.Namespace, p.Name)
	nodeID := resourceID(KindNode, "", p.Spec.NodeName)

	g.AddNode(ResourceNode{
		ID:        podID,
		Kind:      KindPod,
		Name:      p.Name,
		Namespace: p.Namespace,
		Labels:    p.Labels,
	})
	g.AddEdge(podID, nodeID, RelRunsOn)

	// Add PVC edges.
	for _, vol := range p.Spec.Volumes {
		if vol.PersistentVolumeClaim == nil {
			continue
		}
		pvc, err := client.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, vol.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
		if err != nil {
			logger.Warn("graph: could not fetch PVC", "pod", p.Name, "pvc", vol.PersistentVolumeClaim.ClaimName, "error", err)
			continue
		}
		if pvc.Spec.VolumeName == "" {
			continue
		}
		volID := resourceID(KindVolume, "", pvc.Spec.VolumeName)
		g.AddNode(ResourceNode{
			ID:   volID,
			Kind: KindVolume,
			Name: pvc.Spec.VolumeName,
		})
		g.AddEdge(podID, volID, RelUsesPVC)
	}
}

// RegisterPod adds/updates a single pod in the graph. Useful for Watch-based
// incremental updates without a full relist.
func (g *DependencyGraph) RegisterPod(p corev1.Pod) {
	if p.Spec.NodeName == "" {
		return
	}
	podID := resourceID(KindPod, p.Namespace, p.Name)
	nodeID := resourceID(KindNode, "", p.Spec.NodeName)
	g.AddNode(ResourceNode{
		ID:        podID,
		Kind:      KindPod,
		Name:      p.Name,
		Namespace: p.Namespace,
		Labels:    p.Labels,
	})
	g.AddEdge(podID, nodeID, RelRunsOn)
}

// UnregisterPod removes a pod from the graph (called on pod delete events).
func (g *DependencyGraph) UnregisterPod(namespace, name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	podID := resourceID(KindPod, namespace, name)
	delete(g.nodes, podID)
	nodeID := g.podToNode[podID]
	delete(g.podToNode, podID)
	if nodeID != "" {
		peers := g.nodeToPods[nodeID]
		filtered := peers[:0]
		for _, p := range peers {
			if p != podID {
				filtered = append(filtered, p)
			}
		}
		g.nodeToPods[nodeID] = filtered
	}
	// Remove edges.
	kept := g.edges[:0]
	for _, e := range g.edges {
		if e.From != podID && e.To != podID {
			kept = append(kept, e)
		}
	}
	g.edges = kept
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// PodID returns the canonical graph ID for a pod.
func PodID(namespace, name string) string {
	return resourceID(KindPod, namespace, name)
}

// NodeID returns the canonical graph ID for a node.
func NodeID(name string) string {
	return resourceID(KindNode, "", name)
}
