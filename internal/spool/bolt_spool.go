package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

const (
	defaultMaxSpoolBytes int64 = 512 * 1024 * 1024 // 512 MiB
	defaultMaxBatchBytes int   = 2 * 1024 * 1024   // 2 MiB (< 4 MiB / 16 MiB gRPC limit)
	evictWatermarkRatio        = 0.80

	recordKindEvent byte = 1
	recordKindSSH   byte = 2
	recordKindLLM   byte = 3
)

var (
	bucketQueue      = []byte("queue")
	bucketDeadLetter = []byte("deadletter")
)

type envelopeMeta struct {
	Key  []byte
	UUID string
	Kind byte
	High bool
	Raw  []byte
}

// BoltSpool provides a crash-resilient local disk WAL queue on Sensors using bbolt.
// It prioritizes KEV/Canary/SSH/LLM entries when evicting above 80% of MaxSpoolBytes,
// respects byte-capped PushEventsBatch sizes (<= 2 MiB), and quarantines rejected items.
type BoltSpool struct {
	mu            sync.Mutex
	db            *bolt.DB
	path          string
	maxSpoolBytes int64
}

// OpenBoltSpool opens or initializes a bbolt WAL spool file at path.
func OpenBoltSpool(path string, maxSpoolBytes int64) (*BoltSpool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir spool dir: %w", err)
	}
	if maxSpoolBytes <= 0 {
		maxSpoolBytes = defaultMaxSpoolBytes
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bbolt spool: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketQueue); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketDeadLetter)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltSpool{db: db, path: path, maxSpoolBytes: maxSpoolBytes}, nil
}

// Close closes the underlying bbolt database.
func (s *BoltSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// EnqueueEvent serializes and writes a TelemetryEvent to the disk spool.
func (s *BoltSpool) EnqueueEvent(ev *honeypotv1.TelemetryEvent) error {
	if ev == nil || ev.GetEventUuid() == "" {
		return errors.New("event missing uuid")
	}
	high := ev.GetIsKev() || ev.GetCanaryKeyId() != "" || ev.GetSeverityScore() >= 70
	raw, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	return s.enqueue(recordKindEvent, high, raw)
}

// EnqueueSSHReplay serializes and writes an SshSessionReplay to the disk spool.
func (s *BoltSpool) EnqueueSSHReplay(rep *honeypotv1.SshSessionReplay) error {
	if rep == nil || rep.GetReplayUuid() == "" {
		return errors.New("ssh replay missing uuid")
	}
	raw, err := proto.Marshal(rep)
	if err != nil {
		return err
	}
	return s.enqueue(recordKindSSH, true, raw)
}

// EnqueueLLMConversation serializes and writes a degraded/offline LlmConversation to the disk spool.
func (s *BoltSpool) EnqueueLLMConversation(lc *honeypotv1.LlmConversation) error {
	if lc == nil || lc.GetConversationUuid() == "" {
		return errors.New("llm conversation missing uuid")
	}
	raw, err := proto.Marshal(lc)
	if err != nil {
		return err
	}
	return s.enqueue(recordKindLLM, true, raw)
}

func (s *BoltSpool) enqueue(kind byte, high bool, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enforceCapLocked(int64(len(payload))); err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQueue)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, seq)
		val := make([]byte, 2+len(payload))
		val[0] = kind
		if high {
			val[1] = 1
		}
		copy(val[2:], payload)
		return b.Put(key, val)
	})
}

// DequeueBatch builds a byte-bounded PushEventsBatchRequest (<= maxBytes) without deleting items yet.
// Caller must invoke AckAndQuarantine after receiving Hive's PushEventsBatchResponse.
func (s *BoltSpool) DequeueBatch(nodeID string, maxBytes int) (req *honeypotv1.PushEventsBatchRequest, uuidToKey map[string][]byte, err error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBatchBytes
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	req = &honeypotv1.PushEventsBatchRequest{NodeId: nodeID}
	uuidToKey = make(map[string][]byte)
	curBytes := len(nodeID) + 32

	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQueue)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) < 2 {
				continue
			}
			kind := v[0]
			payload := v[2:]
			itemBytes := len(payload) + 16
			if len(uuidToKey) > 0 && curBytes+itemBytes > maxBytes {
				break
			}
			keyCopy := append([]byte(nil), k...)
			switch kind {
			case recordKindEvent:
				var ev honeypotv1.TelemetryEvent
				if uErr := proto.Unmarshal(payload, &ev); uErr != nil {
					continue
				}
				req.Events = append(req.Events, &ev)
				uuidToKey[ev.GetEventUuid()] = keyCopy
			case recordKindSSH:
				var rep honeypotv1.SshSessionReplay
				if uErr := proto.Unmarshal(payload, &rep); uErr != nil {
					continue
				}
				req.SshReplays = append(req.SshReplays, &rep)
				uuidToKey[rep.GetReplayUuid()] = keyCopy
			case recordKindLLM:
				var lc honeypotv1.LlmConversation
				if uErr := proto.Unmarshal(payload, &lc); uErr != nil {
					continue
				}
				req.LlmConversations = append(req.LlmConversations, &lc)
				uuidToKey[lc.GetConversationUuid()] = keyCopy
			}
			curBytes += itemBytes
		}
		return nil
	})
	return req, uuidToKey, err
}

// AckAndQuarantine deletes committed items from queue and moves dead-lettered items out of the retry head.
func (s *BoltSpool) AckAndQuarantine(uuidToKey map[string][]byte, ackedUUIDs, deadletterUUIDs []string) error {
	if len(ackedUUIDs) == 0 && len(deadletterUUIDs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		q := tx.Bucket(bucketQueue)
		dl := tx.Bucket(bucketDeadLetter)
		for _, id := range ackedUUIDs {
			if k, ok := uuidToKey[id]; ok {
				_ = q.Delete(k)
			}
		}
		for _, id := range deadletterUUIDs {
			if k, ok := uuidToKey[id]; ok {
				if val := q.Get(k); val != nil {
					_ = dl.Put(k, val)
				}
				_ = q.Delete(k)
			}
		}
		return nil
	})
}

// Stats returns queued item count, dead-letter count, and approximate queued payload bytes.
func (s *BoltSpool) Stats() (queuedCount int, deadLetterCount int, payloadBytes int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.db.View(func(tx *bolt.Tx) error {
		q := tx.Bucket(bucketQueue)
		dl := tx.Bucket(bucketDeadLetter)
		c := q.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			queuedCount++
			payloadBytes += int64(len(v))
		}
		c2 := dl.Cursor()
		for k, _ := c2.First(); k != nil; k, _ = c2.Next() {
			deadLetterCount++
		}
		return nil
	})
	return
}

func (s *BoltSpool) enforceCapLocked(incomingBytes int64) error {
	info, err := os.Stat(s.path)
	var currentSize int64
	if err == nil {
		currentSize = info.Size()
	}
	// Trigger cleanup if file size OR logical payload exceeds 80% watermark
	watermark := int64(float64(s.maxSpoolBytes) * evictWatermarkRatio)
	var logicalBytes int64
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketQueue).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			logicalBytes += int64(len(v))
		}
		return nil
	})
	if currentSize+incomingBytes <= watermark && logicalBytes+incomingBytes <= watermark {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		q := tx.Bucket(bucketQueue)
		var lowKeys [][]byte
		var allKeys [][]byte
		var freed int64
		need := (logicalBytes + incomingBytes) - watermark
		if need < incomingBytes {
			need = incomingBytes
		}
		c := q.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			kCopy := append([]byte(nil), k...)
			allKeys = append(allKeys, kCopy)
			if len(v) >= 2 && v[1] == 0 {
				lowKeys = append(lowKeys, kCopy)
			}
		}
		for _, k := range lowKeys {
			if freed >= need {
				break
			}
			if v := q.Get(k); v != nil {
				freed += int64(len(v))
			}
			_ = q.Delete(k)
		}
		// If still above maxSpoolBytes even after clearing low-severity records, drop oldest entries
		if currentSize+incomingBytes > s.maxSpoolBytes || freed < need {
			for _, k := range allKeys {
				if freed >= need {
					break
				}
				if v := q.Get(k); v != nil {
					freed += int64(len(v))
					_ = q.Delete(k)
				}
			}
		}
		return nil
	})
}
