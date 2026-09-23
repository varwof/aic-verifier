// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"
)

// HashLeaf computes the SHA256 hash of a Merkle tree leaf node.
// Finding 22: the leaf is domain-separated (prefix 0x00) from internal node
// hashes so a leaf hash can never be presented as an internal node hash or
// vice versa.
func HashLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

// HashNode computes the SHA256 hash of a Merkle tree internal node.
// Finding 22: internal nodes use a distinct domain prefix (0x01) so lone-leaf
// roots (HashLeaf, 0x00) cannot collide with node hashes.
func HashNode(left, right []byte) []byte {
	h := sha256.Sum256(append(append([]byte{0x01}, left...), right...))
	return h[:]
}

// MerkleTree is a Merkle hash tree used for tamper-proof audit chains.
type MerkleTree struct {
	leaves [][]byte
	levels [][][]byte
	root   []byte
}

// NewMerkleTree creates a Merkle tree from leaf data.
func NewMerkleTree(leaves [][]byte) *MerkleTree {
	m := &MerkleTree{}
	if len(leaves) == 0 {
		return m
	}
	m.leaves = leaves
	current := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		current[i] = HashLeaf(leaf)
	}
	m.levels = append(m.levels, current)
	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, HashNode(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		m.levels = append(m.levels, next)
		current = next
	}
	if len(current) > 0 {
		m.root = current[0]
	}
	return m
}

// Root returns the Merkle tree root hash.
func (m *MerkleTree) Root() []byte {
	return m.root
}

// RootHex returns the root hash as a hex-encoded string.
func (m *MerkleTree) RootHex() string {
	if m.root == nil {
		return ""
	}
	return hex.EncodeToString(m.root)
}

// ProofStep is a single step in a Merkle audit proof, containing a sibling hash and direction.
type ProofStep struct {
	Sibling []byte `json:"sibling"`
	Left    bool   `json:"left"`
}

// Proof computes the audit proof path for a given leaf index.
func (m *MerkleTree) Proof(leafIndex int) ([]ProofStep, error) {
	if leafIndex < 0 || leafIndex >= len(m.leaves) {
		return nil, fmt.Errorf("merkle: leaf index %d out of range", leafIndex)
	}
	var proof []ProofStep
	idx := leafIndex
	for level := 0; level < len(m.levels)-1; level++ {
		nodes := m.levels[level]
		if idx%2 == 0 {
			if idx+1 < len(nodes) {
				proof = append(proof, ProofStep{Sibling: nodes[idx+1], Left: false})
			}
		} else {
			proof = append(proof, ProofStep{Sibling: nodes[idx-1], Left: true})
		}
		idx /= 2
	}
	return proof, nil
}

// VerifyProof verifies a Merkle audit proof.
func VerifyProof(leaf []byte, proof []ProofStep, root []byte) bool {
	hash := HashLeaf(leaf)
	for _, step := range proof {
		if step.Left {
			hash = HashNode(step.Sibling, hash)
		} else {
			hash = HashNode(hash, step.Sibling)
		}
	}
	return len(hash) > 0 && len(root) > 0 && bytes.Equal(hash, root)
}

// VerifyProofBounded is like VerifyProof but enforces a maximum proof length
// (finding 22): a proof for a tree with n leaves has at most ceil(log2 n) steps,
// so any longer proof is rejected regardless of hash match.
func VerifyProofBounded(leaf []byte, proof []ProofStep, root []byte, maxProofLen int) bool {
	if maxProofLen >= 0 && len(proof) > maxProofLen {
		return false
	}
	return VerifyProof(leaf, proof, root)
}

// SealedTree is a sealed Merkle tree batch with root hash and predecessor link.
type SealedTree struct {
	BatchNumber int    `json:"batch"`
	Timestamp   string `json:"timestamp"`
	Previous    string `json:"previous_root"`
	Root        string `json:"root"`
	Size        int    `json:"size"`
}

// AuditChain manages a sequence of Merkle tree batches for audit trail integrity.
type AuditChain struct {
	mu        sync.Mutex
	trees     []*SealedTree
	batchSize int
	onSeal    func(root []byte)
}

// NewAuditChain creates an audit chain.
func NewAuditChain(batchSize int, onSeal func(root []byte)) *AuditChain {
	if batchSize <= 0 {
		batchSize = 1000
	}
	return &AuditChain{
		batchSize: batchSize,
		onSeal:    onSeal,
	}
}

// Seal seals a batch of audit entries into a Merkle tree.
func (c *AuditChain) Seal(entries [][]byte, previousRoot string) *SealedTree {
	c.mu.Lock()
	defer c.mu.Unlock()

	tree := NewMerkleTree(entries)
	st := &SealedTree{
		BatchNumber: len(c.trees),
		Timestamp:   fmt.Sprintf("%d", time.Now().Unix()),
		Previous:    previousRoot,
		Root:        tree.RootHex(),
		Size:        len(entries),
	}
	c.trees = append(c.trees, st)

	if c.onSeal != nil {
		c.onSeal(tree.Root())
	}
	return st
}

// SealChecked seals a batch like Seal but enforces chain continuity (finding 8):
// when the chain is non-empty, previousRoot must equal the latest root; passing
// an empty previousRoot for a non-empty chain is refused. Tamper-evidence is
// only meaningful if every batch links to its predecessor.
func (c *AuditChain) SealChecked(entries [][]byte, previousRoot string) (*SealedTree, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trees) > 0 {
		last := c.trees[len(c.trees)-1].Root
		if previousRoot == "" {
			return nil, fmt.Errorf("audit chain: batch %d must link to previous root (got empty previous_root)", len(c.trees))
		}
		if previousRoot != last {
			return nil, fmt.Errorf("audit chain: previous_root %q does not match latest root %q (continuity broken)", previousRoot, last)
		}
	}

	tree := NewMerkleTree(entries)
	st := &SealedTree{
		BatchNumber: len(c.trees),
		Timestamp:   fmt.Sprintf("%d", time.Now().Unix()),
		Previous:    previousRoot,
		Root:        tree.RootHex(),
		Size:        len(entries),
	}
	c.trees = append(c.trees, st)
	if c.onSeal != nil {
		c.onSeal(tree.Root())
	}
	return st, nil
}

// VerifyContinuity checks that every batch (after the first) links to its
// predecessor's root, so a reordered/inserted/deleted batch is detected
// (finding 8).
func (c *AuditChain) VerifyContinuity() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, st := range c.trees {
		if i == 0 {
			continue
		}
		if st.Previous != c.trees[i-1].Root {
			return fmt.Errorf("audit chain discontinuity at batch %d: previous=%q want=%q",
				i, st.Previous, c.trees[i-1].Root)
		}
	}
	return nil
}

// Verify verifies the audit proof for a given batch.
func (c *AuditChain) Verify(batchNumber int, leaf []byte, proof []ProofStep) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if batchNumber < 0 || batchNumber >= len(c.trees) {
		return false, fmt.Errorf("audit chain: batch %d not found", batchNumber)
	}
	st := c.trees[batchNumber]
	root, err := hex.DecodeString(st.Root)
	if err != nil {
		return false, fmt.Errorf("audit chain: invalid root hash: %w", err)
	}
	// Finding 22: bound proof length by tree height (ceil(log2 size)).
	maxProof := 0
	if st.Size > 1 {
		maxProof = int(math.Ceil(math.Log2(float64(st.Size))))
	}
	return VerifyProofBounded(leaf, proof, root, maxProof), nil
}

// LatestRoot returns the root hash (hex) of the most recent batch.
func (c *AuditChain) LatestRoot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.trees) == 0 {
		return ""
	}
	return c.trees[len(c.trees)-1].Root
}

// LatestRootBytes returns the root hash (raw bytes) of the most recent batch.
func (c *AuditChain) LatestRootBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.trees) == 0 {
		return nil
	}
	st := c.trees[len(c.trees)-1]
	root, _ := hex.DecodeString(st.Root)
	return root
}

// BatchCount returns the number of sealed batches.
func (c *AuditChain) BatchCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.trees)
}

// Dump exports a text summary of all batches.
func (c *AuditChain) Dump() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var s string
	for _, st := range c.trees {
		s += fmt.Sprintf("%d|%s|%s|%s|%d\n",
			st.BatchNumber, st.Timestamp, st.Previous, st.Root, st.Size)
	}
	return s
}

// GetTree returns the sealed tree for a given batch number.
func (c *AuditChain) GetTree(batchNumber int) *SealedTree {
	c.mu.Lock()
	defer c.mu.Unlock()
	if batchNumber < 0 || batchNumber >= len(c.trees) {
		return nil
	}
	return c.trees[batchNumber]
}

// JSON-friendly types for the verify API

// ProofStepJSON is the JSON representation of an audit proof step.
type ProofStepJSON struct {
	Sibling string `json:"sibling"`
	Left    bool   `json:"left"`
}

// VerifyRequest is an audit verification request.
type VerifyRequest struct {
	Batch int             `json:"batch"`
	Leaf  string          `json:"leaf"`
	Proof []ProofStepJSON `json:"proof"`
}

// VerifyResponse is an audit verification response.
type VerifyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// VerifyJSON verifies an audit proof based on a JSON request.
func (c *AuditChain) VerifyJSON(req *VerifyRequest) *VerifyResponse {
	leaf, err := hex.DecodeString(req.Leaf)
	if err != nil {
		return &VerifyResponse{Error: "invalid leaf encoding: " + err.Error()}
	}
	var proof []ProofStep
	for _, p := range req.Proof {
		sibling, err := hex.DecodeString(p.Sibling)
		if err != nil {
			return &VerifyResponse{Error: "invalid sibling encoding: " + err.Error()}
		}
		proof = append(proof, ProofStep{Sibling: sibling, Left: p.Left})
	}
	ok, err := c.Verify(req.Batch, leaf, proof)
	if err != nil {
		return &VerifyResponse{Error: err.Error()}
	}
	return &VerifyResponse{Valid: ok}
}
