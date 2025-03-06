package manager

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Idx struct {
	Start int64
	End   int64
}

type Manager struct {
	Index    map[string]Idx
	Path     string
	Channel  chan string
	status   string
	dataFile *os.File
	idxFile  *os.File
	mutex    sync.RWMutex
}

// NewManager initializes a Manager struct
func NewManager(path string) *Manager {
	if path == "" {
		path = "/tmp"
	}

	return &Manager{
		Index:   make(map[string]Idx),
		Path:    path,
		Channel: make(chan string),
		status:  "idle",
	}
}

// Start initializes files, indexes, and starts the loop
func (m *Manager) Start() error {
	if _, err := os.Stat(m.Path); os.IsNotExist(err) {
		if err := os.MkdirAll(m.Path, 0755); err != nil {
			return err
		}
	}

	var err error

	// Open/create data file
	m.dataFile, err = os.OpenFile(m.Path+"/data.bin", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	// Open/create index file
	m.idxFile, err = os.OpenFile(m.Path+"/.idx", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	if err = m.loadIndex(); err != nil {
		return err
	}

	go m.loop()
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

		key := parts[0]
		var start, end int64
		_, err := fmt.Sscanf(parts[1]+" "+parts[2], "%d %d", &start, &end)
		if err != nil {
			continue
		}

		m.Index[key] = Idx{Start: start, End: end}
	}

	return scanner.Err()
}

func (m *Manager) loop() {
	m.status = "ready"
	for msg := range m.Channel {
		commands := strings.Fields(msg)

		switch commands[0] {
		case "exit":
			m.status = "exiting"
			close(m.Channel)
			return
		case "status":
			fmt.Println("Status:", m.status)
		case "add":
			m.handleAdd(commands[1:])
		case "get":
			fmt.Println(m.GetData(commands[1]))
		case "delete":
			m.DeleteData(commands[1])
		default:
			fmt.Println("Available commands: exit, status, add <key> <json>, get <key>, delete <key>")
		}
	}
}

func (m *Manager) handleAdd(args []string) {
	if len(args)%2 != 0 {
		fmt.Println("Invalid ADD command format. Use: add <key> <json>")
		return
	}

	for i := 0; i < len(args); i += 2 {
		key, jsonData := args[i], args[i+1]
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
			fmt.Println("JSON parse error:", err)
			continue
		}
		if err := m.AddData(key, jsonData); err != nil {
			fmt.Println("Error adding data:", err)
		}
	}
}

func (m *Manager) rewriteFiles() error {
	m.dataFile.Truncate(0)
	m.dataFile.Seek(0, 0)

	m.idxFile.Truncate(0)
	m.idxFile.Seek(0, 0)

	writerData := bufio.NewWriter(m.dataFile)
	writerIdx := bufio.NewWriter(m.idxFile)

	var cursor int64

	for key, idx := range m.Index {
		data := make([]byte, idx.End-idx.Start)
		if _, err := m.dataFile.ReadAt(data, idx.Start); err != nil {
			return err
		}

		length, err := writerData.Write(data)
		if err != nil {
			return err
		}

		fmt.Fprintf(writerIdx, "%s,%d,%d\n", key, cursor, cursor+int64(length))
		m.Index[key] = Idx{Start: cursor, End: cursor + int64(len(data))}
		cursor += int64(len(data))

		// Ensure data is flushed periodically if the file is very large.
		writerIdx.Flush()
		writerIdx.Flush()
	}

	writerIdx.Flush()
	writerIdx.Flush()
	return nil
}

// AddData correctly updating the data and index files
func (m *Manager) AddData(key, data string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// If already exists, delete first to avoid duplicates
	if _, exists := m.Index[key]; exists {
		if err := m.deletePhysicalKey(key); err != nil {
			return err
		}
	}

	info, err := m.dataFile.Stat()
	if err != nil {
		return err
	}

	start := info.Size()
	length, err := m.dataFile.WriteAt([]byte(data), start)
	if err != nil {
		return err
	}

	end := start + int64(length)
	m.Index[key] = Idx{Start: start, End: end}

	if err := m.rewriteIndex(); err != nil {
		return err
	}

	return nil
}

// deletePhysicalKey removes the data associated with the key from the data file
func (m *Manager) deletePhysicalKey(key string) error {
	idx, exists := m.Index[key]
	if !exists {
		return fmt.Errorf("key %s not found", key)
	}

	// Remove the data from the data file
	data := make([]byte, idx.End-idx.Start)
	if _, err := m.dataFile.ReadAt(data, idx.Start); err != nil {
		return err
	}

	// Update the index
	delete(m.Index, key)

	return nil
}

// rewriteIndex persists current index map to idxFile.
func (m *Manager) rewriteIndex() error {
	m.idxFile.Truncate(0)
	m.idxFile.Seek(0, 0)

	writer := bufio.NewWriter(m.idxFile)
	for k, v := range m.Index {
		if _, err := fmt.Fprintf(writer, "%s,%d,%d\n", k, v.Start, v.End); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// DeleteData removes the data physically from the file and updates the index properly
func (m *Manager) DeleteData(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	_, exists := m.Index[key]
	if !exists {
		return fmt.Errorf("key %s not found", key)
	}

	// remove from index map
	delete(m.Index, key)

	// Rewrite the data file
	tempFilePath := m.Path + "/temp_data.bin"
	tempFile, err := os.OpenFile(tempFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	var cursor int64
	writer := bufio.NewWriter(tempFile)

	// recreate index and data file
	for k, idx := range m.Index {
		data := make([]byte, idx.End-idx.Start)
		if _, err := m.dataFile.ReadAt(data, idx.Start); err != nil {
			tempFile.Close()
			return err
		}

		n, err := writer.Write(data)
		if err != nil {
			tempFile.Close()
			return err
		}

		// update the index directly
		m.Index[k] = Idx{
			Start: cursor,
			End:   cursor + int64(n),
		}
		cursor += int64(n)
	}

	writer.Flush()
	tempFile.Close()
	m.dataFile.Close()

	// Replace the original file with the temp updated file
	if err := os.Rename(tempFilePath, m.Path+"/data.bin"); err != nil {
		return err
	}

	// reopen file handles
	m.dataFile, err = os.OpenFile(m.Path+"/data.bin", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	// rewrite index file as well
	if err := m.rewriteIndex(); err != nil {
		return err
	}

	return nil
}

func (m *Manager) rebuildIndexFile() error {
	m.idxFile.Truncate(0)
	m.idxFile.Seek(0, 0)

	writer := bufio.NewWriter(m.idxFile)
	for key, idx := range m.Index {
		if _, err := fmt.Fprintf(writer, "%s,%d,%d\n", key, idx.Start, idx.End); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// GetData reads data from the data file using provided key
func (m *Manager) GetData(key string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	idx, exists := m.Index[key]
	if !exists {
		return "", fmt.Errorf("key %s not found", key)
	}

	data := make([]byte, idx.End-idx.Start)
	if _, err := m.dataFile.ReadAt(data, idx.Start); err != nil {
		return "", err
	}

	return string(data), nil
}

// Status returns current status
func (m *Manager) Status() string {
	return m.status
}

// Stop safely shuts down the Manager
func (m *Manager) Stop() {
	m.Channel <- "exit"
	m.dataFile.Close()
	m.idxFile.Close()
	m.status = "stopped"
}
