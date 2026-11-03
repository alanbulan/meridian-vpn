//go:build linux

package nmvpn

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

// FileActivationJournal owns one private directory for an entire manager
// transaction. The directory must not be shared with a publication Controller.
// It uses FileJournal's path, ownership and lifetime-lock protections. Reusing
// the same filename deliberately makes either journal reject the other's schema
// rather than mistake a record of the other kind for an empty directory.
// Only identifiers and transaction phase are stored, never a profile or secrets.
// There is no public Clear: this slice cannot prove host-network cleanup.
type FileActivationJournal struct{ storage *FileJournal }

func NewFileActivationJournal(path string) (*FileActivationJournal, error) {
	s, err := NewFileJournal(path)
	if err != nil {
		return nil, err
	}
	return &FileActivationJournal{storage: s}, nil
}

func (j *FileActivationJournal) LoadActivation() (*ActivationRecord, error) {
	if j == nil || j.storage == nil {
		return nil, os.ErrClosed
	}
	s := j.storage
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return nil, os.ErrClosed
	}
	fd, err := syscall.Openat(int(s.dir.Fd()), journalName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == syscall.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), journalName)
	defer f.Close()
	if err = privateRegular(fd); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil || len(data) > journalLimit {
		return nil, errors.New("activation journal unreadable or oversized")
	}
	if err = activationJSONKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r ActivationRecord
	if err = dec.Decode(&r); err != nil {
		return nil, errors.New("invalid activation journal")
	}
	if err = validateActivationRecord(r); err != nil {
		return nil, err
	}
	return &r, nil
}

// encoding/json folds field names and accepts duplicate keys. This flat schema
// requires each canonical field exactly once, with no containers or nulls.
func activationJSONKeys(data []byte) error {
	bad := errors.New("noncanonical activation journal")
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return bad
	}
	seen := make(map[string]bool, 11)
	for dec.More() {
		tok, err = dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] {
			return bad
		}
		switch key {
		case "Version", "BootID", "BusID", "Owner", "PluginOwner", "UUID", "Interface", "Nonce", "ConnectionPath", "ActivePath", "Phase":
		default:
			return bad
		}
		seen[key] = true
		value, err := dec.Token()
		if err != nil {
			return bad
		}
		if key == "Version" {
			if n, ok := value.(float64); !ok || n != 1 {
				return bad
			}
		} else if _, ok := value.(string); !ok {
			return bad
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') || len(seen) != 11 {
		return bad
	}
	if _, err = dec.Token(); err != io.EOF {
		return bad
	}
	return nil
}

func (j *FileActivationJournal) SaveActivation(r ActivationRecord) error {
	if j == nil || j.storage == nil {
		return os.ErrClosed
	}
	s := j.storage
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return os.ErrClosed
	}
	if err := validateActivationRecord(r); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil || len(data)+1 > journalLimit {
		return errors.New("activation journal encoding failed")
	}
	data = append(data, '\n')
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	name := ".activation-" + hex.EncodeToString(token[:]) + ".tmp"
	fd, err := syscall.Openat(int(s.dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer syscall.Unlinkat(int(s.dir.Fd()), name)
	if err = syscall.Fchmod(fd, 0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = syscall.Renameat(int(s.dir.Fd()), name, int(s.dir.Fd()), journalName); err != nil {
		return err
	}
	// Failure here is uncertain durability. Never remove the possible new record.
	return s.dir.Sync()
}

func (j *FileActivationJournal) Close() error {
	if j == nil || j.storage == nil {
		return nil
	}
	return j.storage.Close()
}
