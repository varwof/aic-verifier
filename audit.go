// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pki "github.com/varwof/types"
)

// AuditAction represents the action type of an audit event.
type AuditAction string

const (
	// ActionConnected indicates the client has connected.
	ActionConnected AuditAction = "connected"
	// ActionDisconnected indicates the client has disconnected.
	ActionDisconnected AuditAction = "disconnected"
	// ActionDenied indicates the connection was rejected.
	ActionDenied AuditAction = "denied"
	// ActionRevoked indicates the certificate has been revoked.
	ActionRevoked AuditAction = "revoked"
	// ActionProxied indicates the proxy forwarding has been established.
	ActionProxied AuditAction = "proxied"
	// ActionCompleted indicates the proxy forwarding has completed.
	ActionCompleted AuditAction = "completed"
	// ActionNoRoute indicates no matching route was found.
	ActionNoRoute AuditAction = "no_route"
	// ActionWSConnect indicates a WebSocket has been connected.
	ActionWSConnect AuditAction = "ws_connect"
	// ActionWSClose indicates a WebSocket has been closed.
	ActionWSClose AuditAction = "ws_close"
	// ActionPluginDecision indicates a plugin decision has been executed.
	ActionPluginDecision AuditAction = "plugin_decision"
	// ActionUnknownConstraint indicates an unknown constraint type was ignored (forward compatibility).
	ActionUnknownConstraint AuditAction = "unknown_constraint"
)

// AuditEntry is an audit log entry that records connection or decision events.
type AuditEntry struct {
	Time           string   `json:"time"`
	Action         string   `json:"action"`
	SrcIP          string   `json:"src_ip"`
	ClientCN       string   `json:"client_cn,omitempty"`
	ClientSerial   string   `json:"client_serial,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Mapping        string   `json:"mapping"`
	Target         string   `json:"target"`
	TargetID       string   `json:"target_id,omitempty"`
	Duration       string   `json:"duration,omitempty"`
	DenyReason     string   `json:"deny_reason,omitempty"`
	BytesIn        int64    `json:"bytes_in,omitempty"`
	BytesOut       int64    `json:"bytes_out,omitempty"`
	TraceId        string   `json:"trace_id,omitempty"`
	SessionId      string   `json:"session_id,omitempty"`
	GatewayId      string   `json:"gateway_id,omitempty"`
	Protocol       string   `json:"protocol,omitempty"`
	AgentId        string   `json:"agent_id,omitempty"`
	SPIFFEID       string   `json:"spiffe_id,omitempty"`
	PrincipalUid   string   `json:"principal_uid,omitempty"`
	DelegationMode int      `json:"delegation_mode,omitempty"`
	Decision       string   `json:"decision,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
	// Level is the audit entry level (INFO/WARN/ERROR). Plugin decisions: allow=INFO,
	// deny/execution error=WARN (spec P2-A-28).
	Level string `json:"level,omitempty"`
	// DaHash is the SHA-256 hex hash of the DelegationAuthorization signatureValue
	// (authorization evidence fingerprint, Task 4: binding authorization evidence to action records).
	DaHash string `json:"da_hash,omitempty"`
	// AICFingerprint is the SHA-256 hex of the AIC extension DER encoding (Task 4).
	AICFingerprint string `json:"aic_fingerprint,omitempty"`
	// PolicyVersion is the policy version effective at decision time (Task 5a: binding decision records to policy version).
	// 0 when PolicyManager is not enabled (omitempty omits from output).
	PolicyVersion uint64 `json:"policy_version,omitempty"`
	// RecordDigest is the input digest (hex) of the evidence record this
	// decision produced (refs[0].Digest).  It pins the audit line to the
	// replayable record chain so the two no longer drift apart; empty when the
	// decision produced no record.
	RecordDigest string `json:"record_digest,omitempty"`
}

// SignedAuditEntry is an audit entry with TSA timestamp signature.
type SignedAuditEntry struct {
	Entry AuditEntry `json:"entry"`
	TST   string     `json:"tst,omitempty"`
}

// RotatingFile is an auto-rotating file that supports size-based rotation and backup count limits.
type RotatingFile struct {
	path    string
	maxSize int64
	maxBak  int
	mu      sync.Mutex
	f       *os.File
	size    int64
}

// NewRotatingFile creates an auto-rotating file instance.
func NewRotatingFile(path string, maxSize int64, maxBak int) (*RotatingFile, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	info, _ := f.Stat()
	return &RotatingFile{
		path:    path,
		maxSize: maxSize,
		maxBak:  maxBak,
		f:       f,
		size:    info.Size(),
	}, nil
}

// Write implements io.Writer with automatic rotation.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	r.f.Close()

	for i := r.maxBak; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", r.path, i)
		prev := fmt.Sprintf("%s.%d", r.path, i-1)
		if i == 1 {
			prev = r.path
		}
		os.Remove(old)
		if _, err := os.Stat(prev); err == nil {
			os.Rename(prev, old)
		}
	}

	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("recreate after rotate: %w", err)
	}
	r.f = f
	r.size = 0
	return nil
}

// Close closes the rotating file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// AuditLogger is the audit log writer that writes in JSON Lines format.
type AuditLogger struct {
	file   string
	w      *RotatingFile
	mu     sync.Mutex
	tsa    *TSAClient
	closed bool

	entries    chan AuditEntry
	done       chan struct{}
	stopped    atomic.Bool
	dropped    atomic.Int64 // count of entries dropped when the buffer was full (M6)
	tsaTimeout time.Duration
	// criticalTimeout bounds how long Log waits to enqueue a security-critical
	// entry before giving up (finding 15). Default 2s.
	criticalTimeout time.Duration
}

// NewAuditLogger creates an audit log writer (returns nil if file is empty).
func NewAuditLogger(file string, tsa *TSAClient, maxSize int64, maxBak int) (*AuditLogger, error) {
	if file == "" {
		return nil, nil
	}
	w, err := NewRotatingFile(file, maxSize, maxBak)
	if err != nil {
		return nil, err
	}
	l := &AuditLogger{
		file:            file,
		w:               w,
		tsa:             tsa,
		entries:         make(chan AuditEntry, 8192),
		done:            make(chan struct{}),
		tsaTimeout:      5 * time.Second,
		criticalTimeout: 2 * time.Second,
	}
	go l.loop()
	return l, nil
}

// Dropped returns the number of audit entries discarded because the buffer was
// full (M6). Data-plane Log calls must never block, so overflow is dropped and
// counted rather than stalling the caller.
func (l *AuditLogger) Dropped() int64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

// isAuditCritical reports whether an entry is security-critical and must never
// be evicted by a buffer-full flood (finding 15): WARN/ERROR levels and
// revocation/denial/decision actions.
func isAuditCritical(entry AuditEntry) bool {
	if entry.Level == "WARN" || entry.Level == "ERROR" {
		return true
	}
	switch AuditAction(entry.Action) {
	case ActionDenied, ActionRevoked, ActionPluginDecision, ActionUnknownConstraint:
		return true
	}
	return false
}

// Log enqueues an audit entry. It never blocks the caller (M6): if the buffer
// is full the entry is dropped and counted. This prevents a slow audit sink
// (e.g. TSA) from stalling the data plane. Security-critical entries
// (WARN/ERROR, revocation/denial actions) are never dropped on the fast path:
// Log waits up to a bounded timeout for them so an attacker flooding the log
// cannot evict the evidence of its own activity (finding 15).
func (l *AuditLogger) Log(entry AuditEntry) {
	if l == nil || l.stopped.Load() {
		return
	}
	entry.Time = time.Now().UTC().Format(time.RFC3339Nano)
	defer func() { recover() }()
	if isAuditCritical(entry) {
		timer := time.NewTimer(l.criticalTimeout)
		defer timer.Stop()
		select {
		case l.entries <- entry:
		case <-timer.C:
			l.dropped.Add(1)
			fmt.Printf("audit: critical entry dropped after %s (action=%s level=%s)\n",
				l.criticalTimeout, entry.Action, entry.Level)
		}
		return
	}
	select {
	case l.entries <- entry:
	default:
		l.dropped.Add(1)
	}
}

func (l *AuditLogger) loop() {
	for entry := range l.entries {
		l.logSync(entry)
	}
	close(l.done)
}

func (l *AuditLogger) logSync(entry AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	signed := SignedAuditEntry{Entry: entry}

	if l.tsa != nil {
		entryJSON, _ := json.Marshal(entry)
		// Bound TSA signing so a slow timestamp authority cannot stall the
		// entire audit write loop (M6).
		done := make(chan []byte, 1)
		go func() {
			tst, serr := l.tsa.Sign(entryJSON)
			if serr != nil {
				done <- nil
				return
			}
			done <- tst
		}()
		var tst []byte
		select {
		case tst = <-done:
		case <-time.After(l.tsaTimeout):
			fmt.Printf("audit: tsa sign timed out after %s (entry will be unsigned)\n", l.tsaTimeout)
		}
		if tst != nil {
			signed.TST = EncodeBase64(tst)
		}
	}

	data, _ := json.Marshal(signed)
	data = append(data, '\n')
	if _, err := l.w.Write(data); err != nil {
		fmt.Printf("audit: write failed: %v\n", err)
	}
}

// File returns the audit log file path.
func (l *AuditLogger) File() string {
	return l.file
}

// Close closes the audit log writer, draining buffered entries.  It is
// idempotent: closing an already-closed logger returns nil instead of
// re-draining the closed channel (which would spin and write garbage forever).
func (l *AuditLogger) Close() error {
	if l == nil || l.w == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	l.stopped.Store(true)
	// Drain any buffered entries before closing the channel so pending audit
	// records are not silently lost (M6).
	for {
		select {
		case entry := <-l.entries:
			l.logSync(entry)
		default:
			close(l.entries)
			<-l.done
			return l.w.Close()
		}
	}
}

// AuditVerifier verifies audit log entries via TSA timestamps.
type AuditVerifier struct {
	tsaClient *TSAClient
}

// VerifyAuditEntry verifies the TSA timestamp signature of an audit entry.
func VerifyAuditEntry(data []byte, tsaClient *TSAClient) error {
	var signed SignedAuditEntry
	if err := json.Unmarshal(data, &signed); err != nil {
		return fmt.Errorf("parse audit entry: %w", err)
	}

	if signed.TST != "" {
		tstDER, err := DecodeBase64(signed.TST)
		if err != nil {
			return fmt.Errorf("decode TST: %w", err)
		}
		entryJSON, _ := json.Marshal(signed.Entry)
		if err := tsaClient.Verify(entryJSON, tstDER); err != nil {
			return fmt.Errorf("TSA verification failed: %w", err)
		}
	}

	return nil
}

// SetV12Fields sets the v1.2 spec extension fields for the audit log.
func (e *AuditEntry) SetV12Fields(protocol, gatewayId, traceId, sessionId, decision string) {
	e.Protocol = protocol
	e.GatewayId = gatewayId
	e.TraceId = traceId
	e.SessionId = sessionId
	e.Decision = decision
}

// AICFingerprint computes the SHA-256 hex fingerprint of the AIC extension DER encoding
// in the certificate. Returns empty string if the certificate has no AIC extension
// (audit field uses omitempty, keeping old entries readable).
func AICFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	var aicExt []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(pki.OIDAIC) {
			aicExt = ext.Value
			break
		}
	}
	if len(aicExt) == 0 {
		return ""
	}
	sum := sha256.Sum256(aicExt)
	return hex.EncodeToString(sum[:])
}

// DAHash computes the SHA-256 hex hash of the DelegationAuthorization signatureValue
// in the AIC (authorization evidence fingerprint). Returns empty string if AIC is missing
// or has no DA signature.
func DAHash(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	aic, err := ParseAIC(cert)
	if err != nil || aic == nil {
		return ""
	}
	return DAHashFromAIC(aic)
}

// DAHashFromAIC computes the SHA-256 hash of the DelegationAuthorization signatureValue
// for a parsed AIC. Returns empty string if no DA signature is present.
func DAHashFromAIC(aic *AIC) string {
	if aic == nil || len(aic.DelegationAuthorization.SignatureValue) == 0 {
		return ""
	}
	sum := sha256.Sum256(aic.DelegationAuthorization.SignatureValue)
	return hex.EncodeToString(sum[:])
}

// WithEvidenceFingerprints populates the audit entry's authorization evidence fingerprint
// fields (Task 4). Returns the original entry for method chaining.
func (e *AuditEntry) WithEvidenceFingerprints(cert *x509.Certificate) *AuditEntry {
	e.AICFingerprint = AICFingerprint(cert)
	e.DaHash = DAHash(cert)
	return e
}

// NewAuditEntryFromConn creates an audit entry from connection information.
func NewAuditEntryFromConn(srcIP, mappingName, target string, cert *x509.Certificate) AuditEntry {
	entry := AuditEntry{
		Action:  string(ActionConnected),
		SrcIP:   srcIP,
		Mapping: mappingName,
		Target:  target,
	}
	if cert != nil {
		entry.ClientCN = cert.Subject.CommonName
		entry.ClientSerial = MaskCertSerial(cert.SerialNumber.Text(16))
		entry.Roles = ExtractRoles(cert)
		entry.SPIFFEID = ExtractSPIFFEIDFromCert(cert)
		if aic, err := ParseAIC(cert); err == nil && aic != nil {
			entry.AgentId = aic.AgentId
			entry.PrincipalUid = aic.PrincipalUid.String()
			entry.DelegationMode = int(aic.DelegationMode)
			for _, c := range aic.Capabilities {
				entry.Capabilities = append(entry.Capabilities, c.CapabilityId)
			}
		}
		// Task 4: binding authorization evidence to action records — AIC fingerprint + DA hash.
		entry.AICFingerprint = AICFingerprint(cert)
		entry.DaHash = DAHash(cert)
	}
	return entry
}

// NewAuditEntryDenied creates an audit entry for a denied connection.
func NewAuditEntryDenied(srcIP, mappingName, target, reason string, cert *x509.Certificate) AuditEntry {
	entry := NewAuditEntryFromConn(srcIP, mappingName, target, cert)
	entry.Action = string(ActionDenied)
	entry.DenyReason = reason
	return entry
}

// AuditDuration computes and sets the duration of an audit entry.
func AuditDuration(start time.Time, entry *AuditEntry) {
	entry.Duration = time.Since(start).Round(time.Millisecond).String()
}

// AuditFilter is the audit log query filter.
type AuditFilter struct {
	Since    time.Time
	Until    time.Time
	Limit    int
	Offset   int
	Sort     string
	Action   string
	ClientCN string
	Serial   string
	Mapping  string
}

const sortDesc = "desc"

// FilterAuditFile filters the audit file by conditions and prints matching entries.
func FilterAuditFile(file string, since time.Time, action string, cn, serial, mapping string) error {
	entries, err := ReadAuditEntries(file, AuditFilter{
		Since:    since,
		Action:   action,
		ClientCN: cn,
		Serial:   serial,
		Mapping:  mapping,
	})
	if err != nil {
		return err
	}
	for _, entry := range entries {
		out, _ := json.Marshal(entry)
		fmt.Println(string(out))
	}
	return nil
}

// ReadAuditEntries reads audit entries by filter.
func ReadAuditEntries(file string, filter AuditFilter) ([]AuditEntry, error) {
	if filter.Sort == sortDesc {
		return readAuditEntriesReverse(file, filter)
	}

	startOffset := int64(0)
	if !filter.Since.IsZero() {
		off, err := FindStartOffsetByTime(file, filter.Since)
		if err == nil {
			startOffset = off
		}
	}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if startOffset > 0 {
		f.Seek(startOffset, 0)
	}

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	skip := filter.Offset

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var signed SignedAuditEntry
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			continue
		}

		e := signed.Entry
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil {
			continue
		}
		if !filter.Since.IsZero() && t.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && t.After(filter.Until) {
			continue
		}
		if filter.ClientCN != "" && e.ClientCN != filter.ClientCN {
			continue
		}
		if filter.Serial != "" && e.ClientSerial != filter.Serial {
			continue
		}
		if filter.Mapping != "" && e.Mapping != filter.Mapping {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		entries = append(entries, e)
		if filter.Limit > 0 && len(entries) >= filter.Limit {
			break
		}
	}

	if entries == nil {
		entries = make([]AuditEntry, 0)
	}
	return entries, scanner.Err()
}

func readAuditEntriesReverse(file string, filter AuditFilter) ([]AuditEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := info.Size()

	var entries []AuditEntry
	var buf []byte
	pos := fileSize
	scanBuf := make([]byte, 4096)
	skip := filter.Offset

	for pos > 0 {
		readSize := int64(len(scanBuf))
		if readSize > pos {
			readSize = pos
		}
		pos -= readSize
		f.ReadAt(scanBuf[:readSize], pos)
		data := append(scanBuf[:readSize], buf...)
		buf = nil

		for {
			idx := strings.LastIndex(string(data), "\n")
			if idx < 0 {
				buf = data
				break
			}
			line := strings.TrimSpace(string(data[idx:]))
			data = data[:idx]
			if line == "" {
				continue
			}

			var signed SignedAuditEntry
			if err := json.Unmarshal([]byte(line), &signed); err != nil {
				continue
			}
			e := signed.Entry
			if filter.Action != "" && e.Action != filter.Action {
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, e.Time)
			if err != nil {
				continue
			}
			if !filter.Until.IsZero() && t.After(filter.Until) {
				continue
			}
			if !filter.Since.IsZero() && t.Before(filter.Since) {
				continue
			}
			if filter.ClientCN != "" && e.ClientCN != filter.ClientCN {
				continue
			}
			if filter.Serial != "" && e.ClientSerial != filter.Serial {
				continue
			}
			if filter.Mapping != "" && e.Mapping != filter.Mapping {
				continue
			}
			if skip > 0 {
				skip--
				continue
			}
			entries = append(entries, e)
			if filter.Limit > 0 && len(entries) >= filter.Limit {
				break
			}
		}
		if filter.Limit > 0 && len(entries) >= filter.Limit {
			break
		}
	}
	if entries == nil {
		entries = make([]AuditEntry, 0)
	}
	return entries, nil
}

// FindStartOffsetByTime binary-searches for the file offset corresponding to a given time.
func FindStartOffsetByTime(file string, target time.Time) (int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()

	lo, hi := int64(0), size
	for lo < hi {
		mid := (lo + hi) / 2
		f.Seek(mid, 0)

		buf := make([]byte, 1)
		for mid < size {
			f.ReadAt(buf, mid)
			if buf[0] == '\n' {
				mid++
				break
			}
			mid++
		}
		if mid >= size {
			hi = (lo + hi) / 2
			continue
		}

		var lineBuf []byte
		for mid < size {
			f.ReadAt(buf, mid)
			if buf[0] == '\n' {
				break
			}
			lineBuf = append(lineBuf, buf[0])
			mid++
		}
		if len(lineBuf) == 0 {
			lo = (lo+hi)/2 + 1
			continue
		}

		var signed SignedAuditEntry
		if err := json.Unmarshal(lineBuf, &signed); err != nil {
			lo = mid + 1
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, signed.Entry.Time)
		if err != nil {
			lo = mid + 1
			continue
		}

		if t.Before(target) {
			lo = mid + 1
		} else {
			hi = (lo + hi) / 2
		}
	}

	return lo, nil
}

// ArchiveAuditFile archives (compress-rotates) the audit log file.
func ArchiveAuditFile(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() == 0 {
		return nil
	}
	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	archivePath := path + "." + ts + ".archived"
	return os.Rename(path, archivePath)
}

// PluginAuditEntry records audit fields for plugin decision events.
type PluginAuditEntry struct {
	Scheme       string `json:"scheme"`
	CapabilityID string `json:"capability_id"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason"`
	ClientCN     string `json:"client_cn,omitempty"`
	Principal    string `json:"principal,omitempty"`
	// Level is the audit level (INFO/WARN). Allow→INFO, deny/execution error→WARN (spec P2-A-28).
	// Empty value defaults to INFO.
	Level string `json:"level,omitempty"`
	// DaHash is the SHA-256 hash of the DelegationAuthorization signatureValue
	// (Task 4: plugin decision entries also bind authorization evidence fingerprints).
	DaHash string `json:"da_hash,omitempty"`
	// PolicyVersion is the policy version effective at decision time (Task 5a).
	PolicyVersion uint64 `json:"policy_version,omitempty"`
}

// LogPluginDecision writes a plugin decision event to the audit log.
// Deny and execution errors are logged as WARN, allow as INFO (spec P2-A-28).
// When entry.Level is empty, it is inferred from Decision ("allow"→INFO, others→WARN).
func LogPluginDecision(logger *AuditLogger, entry PluginAuditEntry) {
	if logger == nil {
		return
	}
	level := entry.Level
	if level == "" {
		if entry.Decision == "allow" {
			level = "INFO"
		} else {
			level = "WARN"
		}
	}
	logger.Log(AuditEntry{
		Action:        string(ActionPluginDecision),
		ClientCN:      entry.ClientCN,
		Mapping:       entry.Scheme,
		Target:        entry.CapabilityID,
		DenyReason:    entry.Reason,
		TargetID:      entry.Decision,
		PrincipalUid:  entry.Principal,
		Level:         level,
		DaHash:        entry.DaHash,
		PolicyVersion: entry.PolicyVersion,
	})
}
