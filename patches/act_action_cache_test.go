package runner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalCIConcurrentGitIgnoreRemoval(t *testing.T) {
	dir := t.TempDir()
	for round := 0; round < 64; round++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules\n"), 0600))
		start := make(chan struct{})
		errs := make(chan error, 32)
		var workers sync.WaitGroup
		for i := 0; i < cap(errs); i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				errs <- removeGitIgnore(context.Background(), dir)
			}()
		}
		close(start)
		workers.Wait()
		close(errs)
		for err := range errs {
			assert.NoError(t, err)
		}
	}
}

func TestLocalCIGitIgnoreRemovalPreservesOtherErrors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, removeGitIgnore(context.Background(), dir))
	invalid := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.Mkdir(invalid, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(invalid, "child"), []byte("x"), 0600))
	assert.Error(t, removeGitIgnore(context.Background(), dir))
}
