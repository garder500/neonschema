package manager

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Idx struct {
	Start int64
	End   int64
}

type Manager struct {
	Index      map[string]Idx
	Path       string
	Channel    chan string
	status     string
	dataFile   *os.File
	idxFile    *os.File
	mutex      sync.RWMutex
	changeCh   chan struct{} // Notify background job
	stopCh     chan struct{} // Graceful shutdown
	syncPeriod time.Duration // configurable rewrite period
}

// NewManager initializes a Manager struct with a default 30s interval for rewrite
func NewManager(path string) *Manager {
	if path == "" {
		path = "/tmp"
	}

	return &Manager{
		Index:      make(map[string]Idx),
		Path:       path,
		Channel:    make(chan string),
		status:     "idle",
		changeCh:   make(chan struct{}, 1),
		stopCh:     make(chan struct{}),
		syncPeriod: 5 * time.Second,
	}
}

func (m *Manager) Start() error {
	if _, err := os.Stat(m.Path); os.IsNotExist(err) {
		if err := os.MkdirAll(m.Path, 0755); err != nil {
			return err
		}
	}

	var err error
	m.dataFile, err = os.OpenFile(m.Path+"/data.bin", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	m.idxFile, err = os.OpenFile(m.Path+"/.idx", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	if err = m.loadIndex(); err != nil {
		return err
	}

	go m.loop()
	go m.startRewriteWorker()

	m.status = "ready"
	return nil
}

func (m *Manager) loadIndex() error {
	scanner := bufio.NewScanner(m.idxFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			continue
		}

		var start, end int64
		if _, err := fmt.Sscanf(parts[1]+" "+parts[2], "%d %d", &start, &end); err != nil {
			continue
		}

		m.Index[parts[0]] = Idx{Start: start, End: end}
	}

	return scanner.Err()
}

func (m *Manager) loop() {
	for msg := range m.Channel {
		commands := strings.Fields(msg)

		switch commands[0] {
		case "exit":
			close(m.stopCh)
			m.status = "exiting"
			close(m.Channel)
			return
		case "status":
			fmt.Println("Status:", m.status)
		case "add":
			m.handleAdd(commands[1:])
		case "get":
			if data, err := m.GetData(commands[1]); err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println(data)
			}
		case "delete":
			if err := m.DeleteData(commands[1]); err != nil {
				fmt.Println("Error:", err)
			}
		default:
			fmt.Println("Commands: exit, status, add <key> <json>, get <key>, delete <key>")
		}
	}
}

func (m *Manager) handleAdd(args []string) {
	if len(args)%2 != 0 {
		fmt.Println("Invalid ADD command. Use format: add <key> <json>")
		return
	}

	for i := 0; i < len(args); i += 2 {
		key, jsonData := args[i], args[i+1]
		if err := json.Unmarshal([]byte(jsonData), &map[string]interface{}{}); err != nil {
			fmt.Println("JSON error:", err)
			continue
		}
		if err := m.AddData(key, jsonData); err != nil {
			fmt.Println("Add error:", err)
		}
	}
}

func (m *Manager) AddData(key, data string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.Index[key]; exists {
		if err := m.deletePhysicalKey(key); err != nil {
			return err
		}
	}

	info, err := m.dataFile.Stat()
	if err != nil {
		return err
	}

	length, err := m.dataFile.WriteAt([]byte(data), info.Size())
	if err != nil {
		return err
	}

	m.Index[key] = Idx{Start: info.Size(), End: info.Size() + int64(length)}

	m.scheduleRewrite()

	return nil
}

func (m *Manager) DeleteData(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.Index[key]; !exists {
		return fmt.Errorf("Key %s not found", key)
	}

	delete(m.Index, key)

	m.scheduleRewrite()

	return nil
}

func (m *Manager) deletePhysicalKey(key string) error {
	if _, ok := m.Index[key]; !ok {
		return nil
	}
	delete(m.Index, key)
	return nil
}

func (m *Manager) scheduleRewrite() {
	select {
	case m.changeCh <- struct{}{}:
	default:
	}
}

func (m *Manager) startRewriteWorker() {
	timer := time.NewTimer(m.syncPeriod)
	defer timer.Stop()

	for {
		select {
		case <-m.changeCh:
			timer.Reset(m.syncPeriod)
		case <-timer.C:
			m.mutex.Lock()
			if err := m.rewriteFiles(); err != nil {
				fmt.Println("Rewrite error:", err)
			}
			m.mutex.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) rewriteFiles() error {
	tmpDataPath := m.Path + "/data.tmp"

	tmpFile, err := os.OpenFile(tmpDataPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(tmpFile)

	var cursor int64
	for key, idx := range m.Index {
		buffer := make([]byte, idx.End-idx.Start)
		if _, err := m.dataFile.ReadAt(buffer, idx.Start); err != nil {
			tmpFile.Close()
			return err
		}

		n, err := writer.Write(buffer)
		if err != nil {
			tmpFile.Close()
			return err
		}

		m.Index[key] = Idx{Start: cursor, End: cursor + int64(n)}
		cursor += int64(n)
	}

	writer.Flush()
	tmpFile.Close()
	m.dataFile.Close()

	if err := os.Rename(tmpDataPath, m.Path+"/data.bin"); err != nil {
		return err
	}

	m.dataFile, err = os.OpenFile(m.Path+"/data.bin", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	return m.rewriteIndex()
}

func (m *Manager) rewriteIndex() error {
	m.idxFile.Truncate(0)
	m.idxFile.Seek(0, 0)

	writer := bufio.NewWriter(m.idxFile)
	for k, v := range m.Index {
		fmt.Fprintf(writer, "%s,%d,%d\n", k, v.Start, v.End)
	}

	return writer.Flush()
}

func (m *Manager) GetData(key string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	idx, exists := m.Index[key]
	if !exists {
		return "", fmt.Errorf("Key %s not found", key)
	}

	buf := make([]byte, idx.End-idx.Start)
	_, err := m.dataFile.ReadAt(buf, idx.Start)

	return string(buf), err
}

func (m *Manager) Status() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.status
}

func (m *Manager) Stop() {
	close(m.Channel)
	close(m.stopCh)
	m.dataFile.Close()
	m.idxFile.Close()
	m.status = "stopped"
}
