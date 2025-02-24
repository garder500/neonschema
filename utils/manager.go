package utils

import (
	"fmt"
	"os"
)

type Idx struct {
	srt int64
	end int64
}

type Manager struct {
	idx   map[string]Idx
	files map[string]*os.File
}

func NewManager() *Manager {
	return &Manager{
		idx:   make(map[string]Idx),
		files: make(map[string]*os.File),
	}
}

func (i Idx) Size() int64 {
	return i.end - i.srt
}

func (i Idx) Empty() bool {
	return i.Size() == 0
}

func (i Idx) Valid() bool {
	return i.srt >= 0 && i.end > i.srt
}

func (m *Manager) GetIdxPath(name string) (string, bool) {
	_, ok := m.idx[name]
	if !ok {
		return "", false
	}
	// the real path of where the idx point is in the name of the 4 first bytes of the idx
	return name[:4], true
}

func (m *Manager) EditIdx(name string, idx Idx) {
	m.idx[name] = idx
}

func (m *Manager) getLastPath() string {
	var path string = "0000.bin"
	// we need to increment that number until it reach 9999
	for k := range m.files {
		path = k
	}

	return path
}

func incrementPath(path string) string {
	// we need to increment that number until it reach 9999
	var pathNumber int
	_, err := fmt.Sscanf(path[4:], "%d", &pathNumber)
	if err != nil {
		return ""
	}

	pathNumber++
	if pathNumber > 9999 {
		return ""
	}

	return fmt.Sprintf("%s%04d.bin", path[:4], pathNumber)
}

func (m *Manager) AddFileHandle() (*os.File, error) {
	path := incrementPath(m.getLastPath())
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	m.files[path] = f
	return f, nil
}

func (m *Manager) AddIdx(name string, srt, end int64) {
	m.idx[name] = Idx{
		srt: srt,
		end: end,
	}
}

func (m *Manager) GetIdx(name string) (Idx, bool) {
	idx, ok := m.idx[name]
	return idx, ok
}

func (m *Manager) GetFileHandle(path string) (*os.File, bool) {
	f, ok := m.files[path]
	return f, ok
}

func (m *Manager) Close() {
	for _, f := range m.files {
		f.Close()
	}
}

func (m *Manager) GetFirstHandle() (*os.File, error) {
	// this function work differently from the original one
	// it returns the first file handle that reply to a size condition, the file need to be less than 1 GB
	for _, f := range m.files {
		info, _ := f.Stat()
		if info.Size() < 1e9 {
			return f, nil
		}
	}

	// if we reach this point, we need to create a new file
	f, err := m.AddFileHandle()
	if err != nil {
		return nil, err
	}

	// we can now return the last file handle
	return f, nil
}
