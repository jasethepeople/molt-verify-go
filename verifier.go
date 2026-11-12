package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	ZERO_HASH          = "0000000000000000000000000000000000000000000000000000000000000000"
	MAX_LEDGER_BYTES   = 32 * 1024 * 1024
	MAX_EVENT_BYTES    = 256 * 1024
	MAX_MANIFEST_BYTES = 1_000_000
)

var FIELD_NAMES = []string{
	"seq", "ts", "type", "actor", "payload", "prev_hash", "pub", "sig", "hash",
}

var (
	HASH_RE            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	SIG_RE             = regexp.MustCompile(`^[0-9a-f]{128}$`)
	ARTIFACT_DIGEST_RE = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type verifyResult struct {
	Valid   bool
	CheckID string
	Reason  string
	Anchor  string // "verified" or "none"
}

func failV(id, reason string) verifyResult {
	return verifyResult{
		Valid:   false,
		CheckID: id,
		Reason:  reason,
		Anchor:  "none",
	}
}

func passV(anchor string) verifyResult {
	if anchor == "" {
		anchor = "none"
	}
	return verifyResult{
		Valid:  true,
		Anchor: anchor,
	}
}

func isIntegerFloat(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && math.Trunc(f) == f
}

func isSafeInteger(f float64) bool {
	return isIntegerFloat(f) && math.Abs(f) <= 9007199254740991
}

func getObjectField(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	obj, ok := v.(map[string]any)
	return obj, ok
}

func sortedStringKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j]) < 0
	})
	return keys
}

func verifyMoltPackage(directory string) verifyResult {
	if !filepath.IsAbs(directory) {
		return failV("V-01", "Evidence path must be absolute.")
	}

	root := filepath.Clean(directory)

	rootInfo, err := os.Lstat(root)
	if err != nil {
		return failV("V-01", fmt.Sprintf("Cannot read package directory: %v", err))
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return failV("V-01", "Evidence package is not a real directory.")
	}

	manifestPath := filepath.Join(root, "manifest.json")
	eventsPath := filepath.Join(root, "events.jsonl")
	publicPath := filepath.Join(root, "ed25519-public.pem")

	var manifestStat os.FileInfo
	var eventsStat os.FileInfo

	for _, p := range []string{manifestPath, eventsPath, publicPath} {
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return failV("V-02", "Manifest, event ledger, or public key is missing or not a regular file.")
		}
		switch p {
		case manifestPath:
			manifestStat = info
		case eventsPath:
			eventsStat = info
		}
	}

	if manifestStat.Size() > MAX_MANIFEST_BYTES || eventsStat.Size() > MAX_LEDGER_BYTES {
		return failV("V-03", "Evidence package exceeds its size limit.")
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return failV("V-02", fmt.Sprintf("Cannot read package control files: %v", err))
	}
	eventsBytes, err := os.ReadFile(eventsPath)
	if err != nil {
		return failV("V-02", fmt.Sprintf("Cannot read package control files: %v", err))
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		return failV("V-02", fmt.Sprintf("Cannot read package control files: %v", err))
	}

	if !utf8.Valid(manifestBytes) || !utf8.Valid(eventsBytes) || !utf8.Valid(publicBytes) {
		return failV("V-04", "Package contains invalid UTF-8 or a truncated multi-byte sequence.")
	}

	eventsText := string(eventsBytes)

	var manifestAny any
	if err := json.Unmarshal(manifestBytes, &manifestAny); err != nil {
		return failV("V-05", "Manifest JSON is invalid or truncated.")
	}

	manifest, ok := manifestAny.(map[string]any)
	if !ok {
		return failV("V-05", "Manifest root is not a JSON object.")
	}

	artifacts, ok := getObjectField(manifest, "artifacts")
	if !ok {
		return failV("V-06", "Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.")
	}
	artifactBytes, ok := getObjectField(manifest, "artifact_bytes")
	if !ok {
		return failV("V-06", "Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.")
	}
	agentKeys, ok := getObjectField(manifest, "agent_pubkeys")
	if !ok {
		return failV("V-06", "Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.")
	}

	ledgerVal, ok := manifest["ledger_bytes"]
	if !ok {
		return failV("V-06", "Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.")
	}
	ledgerFloat, ok := ledgerVal.(float64)
	if !ok || !isSafeInteger(ledgerFloat) || ledgerFloat < 0 {
		return failV("V-06", "Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.")
	}

	if len(artifacts) != len(artifactBytes) {
		return failV("V-06", "Manifest artifact_bytes must cover every artifact.")
	}

	if len(eventsText) > 0 && !strings.HasSuffix(eventsText, "\n") {
		return failV("V-04", "events.jsonl is truncated: final line has no newline.")
	}

	if int64(len(eventsText)) != int64(ledgerFloat) {
		return failV("V-04", "events.jsonl byte count does not match manifest.ledger_bytes.")
	}

	block, _ := pem.Decode(publicBytes)
	if block == nil {
		return failV("V-07", "Cannot parse Ed25519 public key: no PEM block found")
	}

	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return failV("V-07", fmt.Sprintf("Cannot parse Ed25519 public key: %v", err))
	}

	publicKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return failV("V-07", "Manifest verifier key is not Ed25519.")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return failV("V-07", "Manifest verifier key encoding is invalid.")
	}

	publicHex := hex.EncodeToString(publicKey)

	for _, name := range sortedStringKeys(artifacts) {
		digestVal := artifacts[name]
		digestStr, ok := digestVal.(string)
		if !ok || !ARTIFACT_DIGEST_RE.MatchString(digestStr) {
			return failV("V-08", fmt.Sprintf("Manifest contains an invalid artifact digest for '%s'.", name))
		}

		expectedVal, ok := artifactBytes[name]
		expectedFloat, ok := expectedVal.(float64)
		if !ok || !isSafeInteger(expectedFloat) || expectedFloat < 0 {
			return failV("V-08", fmt.Sprintf("Manifest contains an invalid byte count for '%s'.", name))
		}

		data, err := readContainedArtifact(root, name)
		if err != nil {
			return failV("V-08", err.Error())
		}

		if int64(len(data)) != int64(expectedFloat) {
			return failV("V-08", fmt.Sprintf("Artifact byte count mismatch for '%s'.", name))
		}

		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != strings.ToLower(digestStr) {
			return failV("V-08", fmt.Sprintf("Artifact digest mismatch for '%s'.", name))
		}
	}

	var rows []string
	if eventsText != "" {
		rows = strings.Split(eventsText, "\n")
		if len(rows) > 0 && rows[len(rows)-1] == "" {
			rows = rows[:len(rows)-1]
		}
	}

	previousRecomputed := ""
	recomputedHashes := make([]string, len(rows))

	for index, line := range rows {
		if line == "" || len(line) > MAX_EVENT_BYTES {
			return failV("V-09", "invalid JSON")
		}

		failure, recomputed, _ := checkEvent(line, index, previousRecomputed, publicKey, publicHex, agentKeys)
		if failure != "" {
			return failV("V-09", failure)
		}

		previousRecomputed = recomputed
		recomputedHashes[index] = recomputed
	}

	anchor := "none"

	if anchorVal, exists := manifest["anchor"]; exists {
		anchorMap, ok := anchorVal.(map[string]any)
		if !ok {
			return failV("V-10", "Manifest anchor is malformed.")
		}

		seqVal, ok := anchorMap["seq"]
		if !ok {
			return failV("V-10", "Manifest anchor is malformed.")
		}
		seqFloat, ok := seqVal.(float64)
		if !ok || !isIntegerFloat(seqFloat) || seqFloat < 0 {
			return failV("V-10", "Manifest anchor is malformed.")
		}

		hashVal, ok := anchorMap["hash"]
		if !ok {
			return failV("V-10", "Manifest anchor is malformed.")
		}
		hashStr, ok := hashVal.(string)
		if !ok || !HASH_RE.MatchString(hashStr) {
			return failV("V-10", "Manifest anchor is malformed.")
		}

		if seqFloat >= float64(len(recomputedHashes)) {
			return failV("V-10", "Anchored event sequence is not present.")
		}
		idx := int(seqFloat)

		if recomputedHashes[idx] != hashStr {
			return failV("V-10", "Anchor hash mismatch.")
		}

		anchor = "verified"
	}

	return passV(anchor)
}

func readContainedArtifact(root, name string) ([]byte, error) {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return nil, errors.New("Manifest contains an unsafe artifact path.")
	}

	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("Manifest contains an unsafe artifact path.")
		}
	}

	path := root
	var finalInfo os.FileInfo

	for i, part := range parts {
		path = filepath.Join(path, part)

		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("ENOENT: %v", err)
			}
			return nil, err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Manifest artifact path traverses a symlink or non-directory.")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("Manifest artifact path traverses a symlink or non-directory.")
		}

		finalInfo = info
	}

	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "" || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("Manifest artifact path escapes the evidence package.")
	}

	if finalInfo == nil || !finalInfo.Mode().IsRegular() {
		return nil, errors.New("Manifest artifact is not a regular file.")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ENOENT: %v", err)
		}
		return nil, err
	}
	return data, nil
}

func checkEvent(
	line string,
	index int,
	previousRecomputed string,
	publicKey ed25519.PublicKey,
	publicHex string,
	agentKeys map[string]any,
) (string, string, map[string]any) {
	parsed, perr := parseJSON(line)
	if perr != nil {
		if perr.canonical {
			return "not canonical", "", nil
		}
		return "invalid JSON", "", nil
	}

	canonicalLine, serr := serializeJSON(parsed)
	if serr != nil {
		return "not canonical", "", nil
	}
	if canonicalLine != line {
		return "not canonical", "", nil
	}

	event, ok := parsed.(map[string]any)
	if !ok {
		event = map[string]any{}
	}

	if len(event) != len(FIELD_NAMES) {
		return "wrong fields", "", event
	}
	for _, field := range FIELD_NAMES {
		if _, ok := event[field]; !ok {
			return "wrong fields", "", event
		}
	}

	seq, seqOK := event["seq"].(float64)
	ts, tsOK := event["ts"].(float64)
	_, typOK := event["type"].(string)
	actor, actorOK := event["actor"].(string)
	prev, prevOK := event["prev_hash"].(string)
	pub, pubOK := event["pub"].(string)
	sig, sigOK := event["sig"].(string)
	hash, hashOK := event["hash"].(string)

	if !seqOK || !isIntegerFloat(seq) || seq < 0 ||
		!tsOK || !isIntegerFloat(ts) || ts < 0 ||
		!typOK ||
		!actorOK ||
		!prevOK || !HASH_RE.MatchString(prev) ||
		!pubOK || !HASH_RE.MatchString(pub) ||
		!sigOK || !SIG_RE.MatchString(sig) ||
		!hashOK || !HASH_RE.MatchString(hash) {
		return "bad field format", "", event
	}

	if pub != publicHex {
		return "actor key not bound", "", event
	}
	boundVal, ok := agentKeys[actor]
	if !ok {
		return "actor key not bound", "", event
	}
	boundStr, ok := boundVal.(string)
	if !ok || boundStr != publicHex {
		return "actor key not bound", "", event
	}

	if seq != float64(index) {
		return "seq out of order", "", event
	}

	if seq == 0 {
		if prev != ZERO_HASH {
			return "chain broken", "", event
		}
	} else {
		if previousRecomputed == "" || prev != previousRecomputed {
			return "chain broken", "", event
		}
	}

	body := map[string]any{
		"seq":     event["seq"],
		"ts":      event["ts"],
		"type":    event["type"],
		"payload": event["payload"],
		"actor":   event["actor"],
	}

	canonicalBody, berr := serializeJSON(body)
	if berr != nil {
		return "hash mismatch", "", event
	}

	sum := sha256.Sum256([]byte(prev + canonicalBody))
	recomputed := hex.EncodeToString(sum[:])

	if hash != recomputed {
		return "hash mismatch", "", event
	}

	hashBytes, err := hex.DecodeString(recomputed)
	if err != nil || len(hashBytes) != 32 {
		return "bad signature", "", event
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "bad signature", "", event
	}

	if !ed25519.Verify(publicKey, hashBytes, sigBytes) {
		return "bad signature", "", event
	}

	return "", recomputed, event
}
