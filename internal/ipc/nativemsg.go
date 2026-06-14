// Package ipc implements native messaging (secure channel) with the Bitwarden
// desktop app to unlock the vault via TouchID biometric authentication.
// Based on static analysis of the Bitwarden clients.
package ipc

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sh1ma/bwpk/internal/bwcrypto"
)

// DefaultProxyPath is the default desktop_proxy path for the macOS desktop app.
const DefaultProxyPath = "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy"

// Client manages the native-messaging secure channel.
type Client struct {
	proxyPath string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	stderr    io.ReadCloser

	appID        string
	userID       string
	rsaPriv      *rsa.PrivateKey
	sharedSecret *bwcrypto.SymmetricKey
	messageID    int
	nowMillis    func() int64
}

// New creates a Client. If proxyPath is empty, the default is used.
// userID is the target account ID sent in the handshake and commands.
func New(proxyPath, userID string) *Client {
	if proxyPath == "" {
		proxyPath = DefaultProxyPath
	}
	return &Client{
		proxyPath: proxyPath,
		userID:    userID,
		appID:     loadOrCreateAppID(),
		nowMillis: func() int64 { return time.Now().UnixMilli() },
	}
}

// Close terminates the proxy process.
func (c *Client) Close() {
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
}

// Start launches desktop_proxy and establishes the secure channel.
func (c *Client) Start() error {
	if _, err := os.Stat(c.proxyPath); err != nil {
		return fmt.Errorf("desktop_proxy not found (%s): %w", c.proxyPath, err)
	}
	c.cmd = exec.Command(c.proxyPath)
	var err error
	if c.stdin, err = c.cmd.StdinPipe(); err != nil {
		return err
	}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	c.stdout = bufio.NewReader(stdout)
	if c.stderr, err = c.cmd.StderrPipe(); err != nil {
		return err
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start desktop_proxy: %w", err)
	}
	// drain the proxy's stderr (print when debugging) to avoid blocking.
	go func() {
		sc := bufio.NewScanner(c.stderr)
		for sc.Scan() {
			if os.Getenv("BWPK_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[proxy] %s\n", sc.Text())
			}
		}
	}()
	return c.handshake()
}

// --- native messaging framing (4-byte LE length + JSON) ---

func (c *Client) writeFrame(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if os.Getenv("BWPK_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[ipc->] %s\n", string(payload))
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := c.stdin.Write(hdr[:]); err != nil {
		return err
	}
	_, err = c.stdin.Write(payload)
	return err
}

func (c *Client) readFrame() (map[string]json.RawMessage, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.stdout, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > 64*1024*1024 {
		return nil, fmt.Errorf("invalid frame length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.stdout, buf); err != nil {
		return nil, err
	}
	if os.Getenv("BWPK_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[ipc<-] %s\n", string(buf))
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, fmt.Errorf("failed to parse frame JSON: %w (%s)", err, string(buf))
	}
	return m, nil
}

// --- handshake ---

func (c *Client) handshake() error {
	// generate an RSA-2048 key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	c.rsaPriv = priv
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}

	// send setupEncryption unencrypted: { appId, message: { command, publicKey, messageId } }
	mid := c.nextID()
	err = c.writeFrame(map[string]any{
		"appId": c.appID,
		"message": map[string]any{
			"command":   "setupEncryption",
			"publicKey": base64.StdEncoding.EncodeToString(spki),
			"userId":    c.userID,
			"messageId": mid,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send setupEncryption (the Bitwarden desktop app may not be running; IPC socket not found): %w", err)
	}

	// wait for responses (connected / setupEncryption / verifyDesktopIPCFingerprint, etc.)
	deadline := time.Now().Add(60 * time.Second)
	notified := false
	for time.Now().Before(deadline) {
		m, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("failed to read handshake response (is the desktop app running? is browser integration enabled?): %w", err)
		}
		cmd := strField(m, "command")
		switch cmd {
		case "connected":
			// proxy connected to the desktop app; keep waiting for setupEncryption
			continue
		case "disconnected":
			return fmt.Errorf("desktop app disconnected (it may not be running)")
		case "setupEncryption":
			if appID := strField(m, "appId"); appID != "" && appID != c.appID {
				continue // addressed to another device
			}
			ss := strField(m, "sharedSecret")
			if ss == "" {
				continue
			}
			enc, err := base64.StdEncoding.DecodeString(ss)
			if err != nil {
				return fmt.Errorf("sharedSecret decode: %w", err)
			}
			// decrypt with RSA-OAEP-SHA1
			dec, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.rsaPriv, enc, nil)
			if err != nil {
				return fmt.Errorf("failed to RSA-decrypt sharedSecret: %w", err)
			}
			c.sharedSecret, err = bwcrypto.Key(dec)
			if err != nil {
				return fmt.Errorf("failed to build shared secret key: %w", err)
			}
			return nil
		case "verifyDesktopIPCFingerprint", "verifyFingerprint":
			if !notified {
				fmt.Fprintln(os.Stderr, "-> A trust confirmation (fingerprint phrase) dialog is shown on the desktop app. Please approve it...")
				notified = true
			}
			continue
		default:
			// ignore others and continue
			continue
		}
	}
	return fmt.Errorf("timed out establishing secure channel")
}

// --- command send/receive ---

// UnlockWithBiometrics requests biometric unlock for the given user and returns the UserKey (64 bytes).
// A TouchID prompt is shown on the desktop side.
func (c *Client) UnlockWithBiometrics(userID string) (*bwcrypto.SymmetricKey, error) {
	resp, err := c.callCommand(map[string]any{
		"command": "unlockWithBiometricsForUser",
		"userId":  userID,
	})
	if err != nil {
		return nil, err
	}
	ukB64 := strField(resp, "userKeyB64")
	if ukB64 == "" {
		// reached when response is false, etc.
		return nil, fmt.Errorf("could not obtain UserKey (biometric was denied or not configured)")
	}
	ukBytes, err := base64.StdEncoding.DecodeString(ukB64)
	if err != nil {
		return nil, fmt.Errorf("userKeyB64 decode: %w", err)
	}
	return bwcrypto.Key(ukBytes)
}

// GetBiometricsStatusForUser returns the user's biometric availability status.
func (c *Client) GetBiometricsStatusForUser(userID string) (string, error) {
	resp, err := c.callCommand(map[string]any{
		"command": "getBiometricsStatusForUser",
		"userId":  userID,
	})
	if err != nil {
		return "", err
	}
	return string(resp["response"]), nil
}

// callCommand sends an encrypted command and returns the decrypted response.
func (c *Client) callCommand(payload map[string]any) (map[string]json.RawMessage, error) {
	if c.sharedSecret == nil {
		return nil, fmt.Errorf("secure channel not established")
	}
	mid := c.nextID()
	payload["messageId"] = mid
	payload["timestamp"] = c.nowMillis()

	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	enc, err := bwcrypto.Encrypt(plain, c.sharedSecret, iv)
	if err != nil {
		return nil, err
	}
	// send EncString in object form (matching postMessage's compatible serialization)
	encObj := map[string]any{
		"encryptedString": enc.String(),
		"encryptionType":  2,
		"data":            base64.StdEncoding.EncodeToString(enc.CT),
		"iv":              base64.StdEncoding.EncodeToString(enc.IV),
		"mac":             base64.StdEncoding.EncodeToString(enc.MAC),
	}
	if err := c.writeFrame(map[string]any{"appId": c.appID, "message": encObj}); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		m, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch strField(m, "command") {
		case "invalidateEncryption":
			return nil, fmt.Errorf("secure channel was invalidated")
		case "disconnected":
			return nil, fmt.Errorf("desktop app disconnected")
		}
		if appID := strField(m, "appId"); appID != "" && appID != c.appID {
			continue
		}
		raw, ok := m["message"]
		if !ok {
			continue
		}
		resp, err := c.decryptResponse(raw)
		if err != nil {
			return nil, err
		}
		// match messageId
		var rid int
		if v, ok := resp["messageId"]; ok {
			_ = json.Unmarshal(v, &rid)
		}
		if rid == mid {
			return resp, nil
		}
		// skip other messageIds (stale responses)
	}
	return nil, fmt.Errorf("response timed out")
}

// decryptResponse decrypts a received message (EncString; string or object) and returns the JSON.
func (c *Client) decryptResponse(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var encStr string
	// string form "2.iv|ct|mac"
	if err := json.Unmarshal(raw, &encStr); err != nil {
		// object form { encryptedString, ... }
		var obj struct {
			EncryptedString string `json:"encryptedString"`
		}
		if err2 := json.Unmarshal(raw, &obj); err2 != nil {
			return nil, fmt.Errorf("unknown message format: %w", err)
		}
		encStr = obj.EncryptedString
	}
	plain, err := bwcrypto.DecryptString(encStr, c.sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plain), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}
	return resp, nil
}

func (c *Client) nextID() int {
	c.messageID++
	return c.messageID
}

// --- appId persistence (to reuse the trust confirmation) ---

func appIDPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "bwpk", "appid")
}

func loadOrCreateAppID() string {
	p := appIDPath()
	if b, err := os.ReadFile(p); err == nil && len(b) >= 36 {
		return string(b[:36])
	}
	id := newUUIDv4()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(id), 0o600)
	return id
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func strField(m map[string]json.RawMessage, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return ""
}
