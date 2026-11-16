package webcve

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitserver "github.com/go-git/go-git/v5/plumbing/transport/server"
)

// GitLure serves a read-only decoy `/.git/*` repository generated with go-git
// supporting BOTH Smart HTTP (`git clone`) and Dumb HTTP (`git-dumper`),
// containing an earlier "deleted" commit exposing signed Canary API keys.
type GitLure struct {
	dotGitDir  string
	fileServer http.Handler
	gitSrv     transport.Transport
	endpoint   *transport.Endpoint
	CanaryID   string
}

// NewGitLure builds a realistic two-commit git repository in stateDir/gitlure and prepares dumb HTTP .git serving.
func NewGitLure(stateDir, aiGatewayURL, openaiKey, anthropicKey, canaryID string) (*GitLure, error) {
	if aiGatewayURL == "" {
		aiGatewayURL = "https://ai-proxy.internal-gw.local"
	}
	if openaiKey == "" {
		openaiKey = "sk-proj-gitlure000000000000000000000000000000000"
	}
	if anthropicKey == "" {
		anthropicKey = "sk-ant-api03-gitlure0000-0000000000000000-000000000000"
	}

	workDir := filepath.Join(stateDir, "repo")
	_ = os.RemoveAll(workDir)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, err
	}

	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		return nil, fmt.Errorf("git plain init: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("git worktree: %w", err)
	}

	// Commit 1: accidentally includes .env.production with live-looking Canary keys
	filesCommit1 := map[string]string{
		"README.md":       "# Internal AI Gateway Worker\n\nPrivate edge proxy for inference workloads.\n",
		".env.production": fmt.Sprintf("NODE_ENV=production\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_BASE_URL=%s\nANTHROPIC_API_KEY=%s\n", strings.TrimRight(aiGatewayURL, "/"), openaiKey, strings.TrimRight(aiGatewayURL, "/"), anthropicKey),
	}
	for name, body := range filesCommit1 {
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(body), 0o644); err != nil {
			return nil, err
		}
		if _, err := wt.Add(name); err != nil {
			return nil, err
		}
	}
	c1Time := time.Now().UTC().Add(-72 * time.Hour)
	_, err = wt.Commit("chore: add initial production inference configuration", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Platform Bot",
			Email: "devops@corp-internal.local",
			When:  c1Time,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("commit 1: %w", err)
	}

	// Commit 2: removes .env.production leaving it recoverable in object history
	if err := os.Remove(filepath.Join(workDir, ".env.production")); err != nil {
		return nil, err
	}
	_, _ = wt.Remove(".env.production")
	if err := os.WriteFile(filepath.Join(workDir, ".gitignore"), []byte(".env*\nnode_modules/\n"), 0o644); err != nil {
		return nil, err
	}
	_, _ = wt.Add(".gitignore")

	headHash, err := wt.Commit("security: untrack committed env secrets before release", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Platform Bot",
			Email: "devops@corp-internal.local",
			When:  c1Time.Add(2 * time.Hour),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("commit 2: %w", err)
	}

	dotGit := filepath.Join(workDir, ".git")

	// Write git-update-server-info metadata (info/refs) and logs/HEAD for dumb HTTP git clients & git-dumper
	headRef, _ := repo.Head()
	refName := "refs/heads/master"
	if headRef != nil {
		refName = headRef.Name().String()
	}
	infoDir := filepath.Join(dotGit, "info")
	_ = os.MkdirAll(infoDir, 0o755)
	_ = os.WriteFile(filepath.Join(infoDir, "refs"), []byte(fmt.Sprintf("%s\t%s\n", headHash.String(), refName)), 0o644)
	_ = os.MkdirAll(filepath.Join(dotGit, "objects", "info"), 0o755)
	_ = os.WriteFile(filepath.Join(dotGit, "objects", "info", "packs"), []byte(""), 0o644)

	// Remove real worktree files so only read-only .git metadata stays exposed if dir ever browsed
	_ = os.Remove(filepath.Join(workDir, "README.md"))
	_ = os.Remove(filepath.Join(workDir, ".gitignore"))

	ep, _ := transport.NewEndpoint("http://localhost/.git")
	srv := gitserver.NewServer(gitserver.MapLoader{ep.String(): repo.Storer})

	return &GitLure{
		dotGitDir:  dotGit,
		fileServer: http.StripPrefix("/.git/", http.FileServer(http.FS(os.DirFS(dotGit)))),
		gitSrv:     srv,
		endpoint:   ep,
		CanaryID:   canaryID,
	}, nil
}

// ServeGitPath handles read-only Smart & Dumb Git HTTP requests beneath /.git/.
func (g *GitLure) ServeGitPath(w http.ResponseWriter, r *http.Request) bool {
	if g == nil {
		return false
	}
	rawPath := r.URL.Path

	// Smart HTTP: GET /.git/info/refs?service=git-upload-pack
	if r.Method == http.MethodGet && rawPath == "/.git/info/refs" && r.URL.Query().Get("service") == "git-upload-pack" {
		sess, err := g.gitSrv.NewUploadPackSession(g.endpoint, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		defer func() { _ = sess.Close() }()
		adv, err := sess.AdvertisedReferencesContext(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.Header().Set("Cache-Control", "no-cache")
		enc := pktline.NewEncoder(w)
		_ = enc.EncodeString("# service=git-upload-pack\n")
		_ = enc.Flush()
		_ = adv.Encode(w)
		return true
	}

	// Smart HTTP: POST /.git/git-upload-pack
	if r.Method == http.MethodPost && rawPath == "/.git/git-upload-pack" {
		sess, err := g.gitSrv.NewUploadPackSession(g.endpoint, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		defer func() { _ = sess.Close() }()
		req := packp.NewUploadPackRequest()
		if err := req.Decode(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		resp, err := sess.UploadPack(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		defer func() { _ = resp.Close() }()
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		w.Header().Set("Cache-Control", "no-cache")
		_ = resp.Encode(w)
		return true
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if rawPath == "/.git" || rawPath == "/.git/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head><title>Index of /.git/</title></head><body><h1>Index of /.git/</h1><a href=\"HEAD\">HEAD</a><br><a href=\"config\">config</a><br><a href=\"logs/HEAD\">logs/HEAD</a><br><a href=\"info/refs\">info/refs</a></body></html>"))
		return true
	}
	if !strings.HasPrefix(rawPath, "/.git/") {
		return false
	}
	rel := strings.TrimPrefix(rawPath, "/.git/")
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, "..") {
		return false
	}
	if _, err := fs.Stat(os.DirFS(g.dotGitDir), filepath.ToSlash(clean)); err != nil {
		http.NotFound(w, r)
		return true
	}
	g.fileServer.ServeHTTP(w, r)
	return true
}
