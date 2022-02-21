package store_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/errorcode"
	"github.com/OpenSlides/openslides-vote-service/decrypt/store"
)

func TestSaveKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tmpPath := t.TempDir()
		s := store.New(tmpPath)

		if err := s.SaveKey("test/5", []byte("key")); err != nil {
			t.Fatalf("SaveKey: %v", err)
		}

		fullpath := path.Join(tmpPath, "test_5_key")
		content, err := os.ReadFile(fullpath)
		if err != nil {
			t.Fatalf("reading keyfile: %v", err)
		}

		if !bytes.Equal(content, []byte("key")) {
			t.Errorf("SaveKey created file with `%s`, expected `key`", content)
		}

		fInfo, err := os.Stat(fullpath)
		if err != nil {
			t.Fatalf("reading file stat: %v", err)
		}

		if fInfo.Mode() != 0400 {
			t.Errorf("created file has mode %s, expected `%s`", fInfo.Mode(), fs.FileMode(0400))
		}
	})

	t.Run("file exists", func(t *testing.T) {
		tmpPath := t.TempDir()
		os.WriteFile(path.Join(tmpPath, "test_5_key"), []byte("old key"), 0400)
		s := store.New(tmpPath)

		if err := s.SaveKey("test/5", []byte("key")); err != errorcode.Exist {
			t.Errorf("SaveKey returned error `%v`, expected `%v`", err, errorcode.Exist)
		}
	})
}

func TestLoadKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tmpPath := t.TempDir()
		os.WriteFile(path.Join(tmpPath, "test_5_key"), []byte("key"), 0400)
		s := store.New(tmpPath)

		got, err := s.LoadKey("test/5")
		if err != nil {
			t.Fatalf("LoadKey returns: %v", err)
		}

		if !bytes.Equal(got, []byte("key")) {
			t.Errorf("LoadKey returned `%s`, expected `key`", got)
		}
	})

	t.Run("key unknown", func(t *testing.T) {
		tmpPath := t.TempDir()
		s := store.New(tmpPath)

		if _, err := s.LoadKey("test/5"); err != errorcode.NotExist {
			t.Errorf("LoadKey retunred `%v`, expected `%v`", err, errorcode.NotExist)
		}
	})
}

func TestValidateSignature(t *testing.T) {
	t.Run("firt time", func(t *testing.T) {
		tmpPath := t.TempDir()
		os.WriteFile(path.Join(tmpPath, "test_5_key"), []byte("key"), 0400)
		s := store.New(tmpPath)

		if err := s.ValidateSignature("test/5", []byte("hash")); err != nil {
			t.Errorf("ValidateSignature: %v", err)
		}

		fullpath := path.Join(tmpPath, "test_5_hash")
		content, err := os.ReadFile(fullpath)
		if err != nil {
			t.Fatalf("reading hash file: %v", err)
		}

		if !bytes.Equal(content, []byte("hash")) {
			t.Errorf("ValidateSignature created file with `%s`, expected `hash`", content)
		}

		fInfo, err := os.Stat(fullpath)
		if err != nil {
			t.Fatalf("reading file stat: %v", err)
		}

		if fInfo.Mode() != 0400 {
			t.Errorf("created file has mode %s, expected `%s`", fInfo.Mode(), fs.FileMode(0400))
		}
	})

	t.Run("second time valid", func(t *testing.T) {
		tmpPath := t.TempDir()
		os.WriteFile(path.Join(tmpPath, "test_5_key"), []byte("key"), 0400)
		os.WriteFile(path.Join(tmpPath, "test_5_hash"), []byte("hash"), 0400)
		s := store.New(tmpPath)

		if err := s.ValidateSignature("test/5", []byte("hash")); err != nil {
			t.Fatalf("ValidateSignature: %v", err)
		}
	})

	t.Run("second time invalid", func(t *testing.T) {
		tmpPath := t.TempDir()
		os.WriteFile(path.Join(tmpPath, "test_5_key"), []byte("key"), 0400)
		os.WriteFile(path.Join(tmpPath, "test_5_hash"), []byte("hash"), 0400)
		s := store.New(tmpPath)

		if err := s.ValidateSignature("test/5", []byte("invalid")); err != errorcode.Invalid {
			t.Fatalf("ValidateSignature returned `%v`, expected `%s`", err, errorcode.Invalid)
		}
	})

	t.Run("unknown poll", func(t *testing.T) {
		tmpPath := t.TempDir()
		s := store.New(tmpPath)

		if err := s.ValidateSignature("test/5", []byte("hash")); err != errorcode.NotExist {
			t.Fatalf("ValidateSignature returned `%v`, expected `%s`", err, errorcode.NotExist)
		}
	})
}

func TestClearPoll(t *testing.T) {
	t.Run("remove files", func(t *testing.T) {
		tmpPath := t.TempDir()
		keyFile := path.Join(tmpPath, "test_5_key")
		hashFile := path.Join(tmpPath, "test_5_hash")
		os.WriteFile(keyFile, []byte("key"), 0400)
		os.WriteFile(hashFile, []byte("hash"), 0400)
		s := store.New(tmpPath)

		if err := s.ClearPoll("test/5"); err != nil {
			t.Fatalf("ClearPoll: %v", err)
		}

		if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("key file not deleted")
		}

		if _, err := os.Stat(hashFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("hash file not deleted")
		}
	})

	t.Run("files not exist", func(t *testing.T) {
		tmpPath := t.TempDir()
		s := store.New(tmpPath)

		if err := s.ClearPoll("test/5"); err != nil {
			t.Fatalf("ClearPoll: %v", err)
		}
	})
}
