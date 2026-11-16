package orchestrator

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// ArtifactMeta holds metadata for a captured payload or downloaded malware sample.
type ArtifactMeta struct {
	SHA256    string
	MD5       string
	Size      int64
	MimeType  string
	SourceURL string
	NodeID    string
	EventUUID string
}

// ArtifactSink receives captured binaries on a Sensor and stages/streams them safely to Hive's UploadArtifact RPC.
type ArtifactSink interface {
	Submit(ctx context.Context, meta ArtifactMeta, data []byte) (string, error)
}

// StagedArtifactSink deduplicates locally by SHA256, writes 0400 copies under stageDir, and uploads via gRPC if mounted.
type StagedArtifactSink struct {
	mu       sync.Mutex
	stageDir string
	seen     map[string]struct{}
	uploader func(ctx context.Context, meta ArtifactMeta, data []byte) error
}

// NewStagedArtifactSink initializes a Sensor-side artifact sink.
func NewStagedArtifactSink(stageDir string, uploader func(ctx context.Context, meta ArtifactMeta, data []byte) error) (*StagedArtifactSink, error) {
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir artifact stage dir: %w", err)
	}
	return &StagedArtifactSink{
		stageDir: stageDir,
		seen:     make(map[string]struct{}),
		uploader: uploader,
	}, nil
}

// Submit computes SHA256/MD5 hashes, stages deduplicated bytes safely on disk, and invokes the uploader if connected.
func (s *StagedArtifactSink) Submit(ctx context.Context, meta ArtifactMeta, data []byte) (string, error) {
	sum256 := sha256.Sum256(data)
	sumMD5 := md5.Sum(data)
	meta.SHA256 = hex.EncodeToString(sum256[:])
	meta.MD5 = hex.EncodeToString(sumMD5[:])
	meta.Size = int64(len(data))
	if meta.MimeType == "" {
		meta.MimeType = "application/octet-stream"
	}

	s.mu.Lock()
	_, already := s.seen[meta.SHA256]
	s.mu.Unlock()

	dst := filepath.Join(s.stageDir, meta.SHA256+".bin")
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		_ = os.WriteFile(dst, data, 0o400)
	}
	if s.uploader != nil && !already {
		if err := s.uploader(ctx, meta, data); err != nil {
			// Do not record seen if upload failed so retry succeeds once Hive reconnects
			return meta.SHA256, err
		}
	}
	s.mu.Lock()
	if len(s.seen) > 10000 {
		s.seen = make(map[string]struct{})
	}
	s.seen[meta.SHA256] = struct{}{}
	s.mu.Unlock()
	return meta.SHA256, nil
}

// StreamUploadArtifact streams a single artifact over SensorControlService.UploadArtifact.
func StreamUploadArtifact(ctx context.Context, client honeypotv1.SensorControlServiceClient, meta ArtifactMeta, data []byte) error {
	if resp, err := client.HasArtifactSHA256(ctx, &honeypotv1.HasArtifactRequest{Sha256: meta.SHA256}); err == nil && resp.GetExists() {
		return nil
	}
	stream, err := client.UploadArtifact(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&honeypotv1.ArtifactChunk{
		Part: &honeypotv1.ArtifactChunk_Metadata{
			Metadata: &honeypotv1.ArtifactMetadata{
				Sha256:    meta.SHA256,
				Md5:       meta.MD5,
				FileSize:  meta.Size,
				MimeType:  meta.MimeType,
				SourceUrl: meta.SourceURL,
				NodeId:    meta.NodeID,
				EventUuid: meta.EventUUID,
			},
		},
	}); err != nil {
		return err
	}
	const chunkSize = 64 * 1024
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&honeypotv1.ArtifactChunk{
			Part: &honeypotv1.ArtifactChunk_Data{Data: data[off:end]},
		}); err != nil {
			return err
		}
	}
	_, err = stream.CloseAndRecv()
	return err
}
