package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// These paths are used for different kinds of storage
const (
	rootsSubPath     = "roots"
	nodeInfoSubPath  = "nodeinfo"
	nodeCredsSubPath = "nodecreds"
)

type FileStorage struct {
	sync.RWMutex
	baseDir     string
	skipCleanup bool
}

// Ensure we implement the Storage interface
var (
	_ nodeenrollment.Storage = (*FileStorage)(nil)
)

// New creates a new object that implements the Storage interface in
// an on-disk directory. This is not currently explicitly thread-safe, although
// it may work without issue in that manner. Call Cleanup() when done with it.
//
// Supported options: WithBaseDirectory, WithSkipCleanup
//
// For safety, if a base directory is specified (that is, it's not a temporary
// directory generated by this function), cleanup is _always_ skipped.
func New(ctx context.Context, opt ...Option) (*FileStorage, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading opts when creating new test storage: %w", err)
	}
	ts := &FileStorage{
		baseDir:     opts.withBaseDirectory,
		skipCleanup: opts.withSkipCleanup,
	}

	const pattern = "nodeenrollment"

	switch ts.baseDir {
	case "":
		ts.baseDir, err = os.MkdirTemp("", pattern)
		if err != nil {
			return nil, fmt.Errorf("error creating temp directory: %w", err)
		}
	default:
		ts.skipCleanup = true
	}

	return ts, nil
}

// Returns the base directory being used, useful for displaying in tests for
// after-test inspection
func (ts *FileStorage) BaseDir() string {
	return ts.baseDir
}

// Cleanup provides a function to clean up after tests
func (ts *FileStorage) Cleanup() {
	if ts.skipCleanup {
		return
	}
	os.RemoveAll(ts.baseDir)
}

// subPathFromMsg determines what subdirectory to use based on which message
// type it is
func subPathFromMsg(msg proto.Message) (string, error) {
	const op = "nodeenrollment.storage.file.(FileStorage).subPathFromMsg"
	switch t := msg.(type) {
	case *types.NodeCredentials:
		return nodeCredsSubPath, nil
	case *types.NodeInformation:
		return nodeInfoSubPath, nil
	case *types.RootCertificates:
		return rootsSubPath, nil
	default:
		return "", fmt.Errorf("(%s) unknown message type %T", op, t)
	}
}

// Store implements the Storage interface.
//
// If the message already exists, it is overwritten.
func (ts *FileStorage) Store(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.file.(FileStorage).Store"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	return ts.storeValue(ctx, msg.GetId(), subPath, msg)
}

// Load implements the Storage interface
func (ts *FileStorage) Load(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.file.(FileStorage).Load"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	err = ts.loadValue(ctx, msg.GetId(), subPath, msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	return nil
}

// Remove implements the Storage interface
func (ts *FileStorage) Remove(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.file.(FileStorage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}
	return ts.removeValue(ctx, msg.GetId(), subPath)
}

// List implements the Storage interface
func (ts *FileStorage) List(ctx context.Context, msg proto.Message) ([]string, error) {
	const op = "nodeenrollment.storage.file.(FileStorage).List"

	switch t := msg.(type) {
	case *types.NodeCredentials,
		*types.NodeInformation,
		*types.RootCertificates:
	default:
		return nil, fmt.Errorf("(%s) unknown message type %T", op, t)
	}

	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return nil, fmt.Errorf("(%s) given messages cannot be listed: %w", op, err)
	}
	return ts.listValues(ctx, subPath)
}

// storeValue is the general function called to store values, taking in an id,
// subpath, and proto message to store
func (ts *FileStorage) storeValue(ctx context.Context, id, subPath string, msg proto.Message) error {
	switch {
	case id == "":
		return errors.New("no id given when storing value")
	case subPath == "":
		return errors.New("no sub path given when storing value")
	case msg == nil:
		return errors.New("nil msg when storing value")
	}

	ts.Lock()
	defer ts.Unlock()

	dirPath := filepath.Join(ts.baseDir, subPath)
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		return fmt.Errorf("error creating necessary directory path at %s: %w", dirPath, err)
	}

	path := filepath.Join(dirPath, id)
	marshaledBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error proto marshaling value: %w", err)
	}

	if err := os.WriteFile(path, marshaledBytes, 0o600); err != nil {
		return fmt.Errorf("error writing value to path %s: %w", path, err)
	}

	return nil
}

// loadValue is the general function for loading a value into the given result
func (ts *FileStorage) loadValue(ctx context.Context, id, subPath string, result proto.Message) error {
	switch {
	case id == "":
		return errors.New("no id given when loading value")
	case subPath == "":
		return errors.New("no sub path given when loading value")
	case result == nil:
		return errors.New("nil result value when loading value")
	}

	ts.RLock()
	defer ts.RUnlock()

	// This list is because the error for a file not found may not be portable,
	// so it ensures that if a value isn't there that we properly error as such
	// with ErrNotFound
	vals, err := ts.listValues(ctx, subPath)
	if err != nil {
		return err
	}
	var found bool
	for _, v := range vals {
		if v == id {
			found = true
			break
		}
	}
	if !found {
		return nodeenrollment.ErrNotFound
	}

	path := filepath.Join(ts.baseDir, subPath, id)

	pathBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading value at path %s: %w", path, err)
	}

	if err := proto.Unmarshal(pathBytes, result); err != nil {
		return fmt.Errorf("error unmarshaling value at path %s: %w", path, err)
	}

	return nil
}

// removeValue is used to remove a message from storage
func (ts *FileStorage) removeValue(ctx context.Context, id, subPath string) error {
	switch {
	case id == "":
		return errors.New("no identifier given when removing value")
	case subPath == "":
		return errors.New("no subPath given when removing value")
	}

	ts.Lock()
	defer ts.Unlock()

	path := filepath.Join(ts.baseDir, subPath, id)

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("error removing value %s: %w", id, err)
	}

	return nil
}

// listValues is used to list values in a subpath
func (ts *FileStorage) listValues(ctx context.Context, subPath string) ([]string, error) {
	if subPath == "" {
		return nil, errors.New("no subPath given when removing value")
	}

	ts.RLock()
	defer ts.RUnlock()

	validPaths, err := getValidPaths(ctx, filepath.Join(ts.baseDir, subPath))
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, path := range validPaths {
		paths = append(paths, filepath.Base(path))
	}

	return paths, nil
}

// getValidPaths returns the set of full paths within the given base path
func getValidPaths(ctx context.Context, basePath string) ([]string, error) {
	f, err := os.Open(basePath)
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("error opening base directory %s: %w", basePath, err)
	}

	dirnames, err := f.Readdirnames(0)
	if err != nil {
		return nil, fmt.Errorf("error reading dirnames from %s: %w", basePath, err)
	}

	validPaths := make([]string, 0, len(dirnames))
	for _, dirname := range dirnames {
		path := filepath.Join(basePath, dirname)
		fi, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("error stat-ing path at %s: %w", path, err)
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		validPaths = append(validPaths, path)
	}

	sort.Strings(validPaths)

	return validPaths, nil
}
