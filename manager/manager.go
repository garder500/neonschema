package manager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack"
)

type fileWriter struct {
	dataFile *os.File
	idxFile  *os.File
}

type Idx struct {
	start int64
	end   int64
}

type Manager struct {
	Index      map[string]Idx
	Path       string // Path to the directory where data will be stored
	Channel    chan string
	status     string
	fileWriter fileWriter
}

func NewManager(path string) *Manager {
	return &Manager{
		Index: make(map[string]Idx),
		Path: func() string {
			if path == "" {
				return "/tmp"
			}
			return path
		}(),
		Channel: make(chan string),
		status:  "idle",
	}
}

func (m *Manager) Start() {
	fmt.Println("Starting manager...")
	// create the data directory
	// first check if the directory exists or not
	if _, err := os.Stat(m.Path); os.IsNotExist(err) {
		// create the directory
		err := os.Mkdir(m.Path, 0755)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}
	}
	// we need to read the index files and load the data into the index map
	// list every directory in the data directory
	files, err := os.ReadDir(m.Path)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}
	for _, file := range files {

		// read the file and load the data into the index
		f, err := os.OpenFile(fmt.Sprintf("%s/%s", m.Path, file.Name()), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		if file.Name() == ".idx" {
			m.fileWriter.idxFile = f
			// here we will add each key to the index map
			// the index file is written as key,start,end
			// each index file is named .idx
			for {
				var key string
				var start, end int64
				// we only need the key and the start and end positions and we add those data to the index
				_, err := fmt.Fscanf(f, "%s,%d,%d\n", &key, &start, &end)
				// if we encounter an empty line, we continue to the next line. This is to avoid reading deleted index
				if key == "" {
					continue
				}
				if err != nil {
					break
				}
				m.Index[key] = Idx{
					start: start,
					end:   end,
				}
			}
		} else {
			m.fileWriter.dataFile = f
		}

	}
	go m.loop()
}

func (m *Manager) Status() string {
	return m.status
}
func (m *Manager) loop() {
	m.status = "ready"
	for {
		select {
		case msg := <-m.Channel:
			fmt.Println(msg)
			// let's parse commands here
			splitted := strings.Split(msg, " ")
			switch splitted[0] {
			case "exit":
				fmt.Println("Exiting manager...")
				m.status = "exiting"
				return
			case "status":
				fmt.Println("Status:", m.status)
			case "add":
				if len(splitted) < 3 {
					fmt.Println("Invalid command")
					break
				}
				// We can add multiple key-value pairs. (key = id, value = json mapping)
				for i := 1; i < len(splitted); i++ {
					if i%2 != 1 {
						continue
					}
					if len(splitted) < i+1 {
						fmt.Println("Invalid command")
						break
					}
					var data map[string]interface{}
					err := json.Unmarshal([]byte(splitted[i+1]), &data)
					if err != nil {
						fmt.Println("Error parsing JSON:", err)
						break
					}
					m.AddData(splitted[i], data)
				}

			case "get":
				if len(splitted) < 2 {
					fmt.Println("Invalid command")
					break
				}
				fmt.Println(m.GetData(splitted[1]))
			case "delete":
				if len(splitted) < 2 {
					fmt.Println("Invalid command")
					break
				}
				m.DeleteData(splitted[1])
			default:
				// return commands list
				fmt.Println("Commands:")
				fmt.Println("exit")
				fmt.Println("status")
				fmt.Println("add <key> <JSON data> <key> <JSON data> ...")
				fmt.Println("get <key>")
				fmt.Println("delete <key>")
			}
		default:
			fmt.Println("status:", m.status)
			fmt.Println("No messages received")
		}
		time.Sleep(1 * time.Second)
	}
}

func (m *Manager) Stop() {
	fmt.Println("Stopping manager...")
	m.Channel <- "exit"
}

func (m *Manager) AddData(key string, data map[string]interface{}) {
	fmt.Printf("adding data with key %s\n", key)
	// we will add data to the index. (we will also lauch a goroutine to write the data to disk)
	m.Index[key] = Idx{
		start: 0,
		end:   0,
	}

	m.writeData(key, data)
}

func (m *Manager) writeData(key string, data map[string]interface{}) {

	// we first need to check if an idx file exists or not
	// if it does, we will append the data to the file
	// if it doesn't, we will create a new file and write the data to it
	if m.fileWriter.idxFile == nil || m.fileWriter.dataFile == nil {
		// create a new file
		idxFile, err := os.OpenFile(fmt.Sprintf("%s/a.idx", m.Path), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			fmt.Println("Error opening idx file:", err)
			return
		}

		// we will write the data to the file
		// we will also write the data to the data file
		dataFile, err := os.OpenFile(m.Path+"/a.bin", os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			fmt.Println("Error opening data file:", err)
			return
		}

		// let's add those file handles to the fileWriter struct
		m.fileWriter.idxFile = idxFile
		m.fileWriter.dataFile = dataFile
	}

	// let's take the first idx and data file
	idxFile := m.fileWriter.idxFile
	dataFile := m.fileWriter.dataFile
	fileStat, err := dataFile.Stat()
	if err != nil {
		fmt.Println("Error getting file stats:", err)
		return
	}
	// we will get the start and end positions
	start := fileStat.Size()
	dataToWrite, err := msgpack.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling data:", err)
		return
	}

	// we will write the data to the file
	totalByte, err := dataFile.WriteAt(dataToWrite, start)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	end := start + int64(totalByte)
	// we will write the index to the index file
	_, err = fmt.Fprintf(idxFile, "%s,%d,%d\n", key, start, end)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	m.Index[key] = Idx{
		start: start,
		end:   end,
	}
	// let's write the index to the file
	dataFile.Sync()
	idxFile.Sync()

}

func (m *Manager) GetData(key string) (string, error) {
	fmt.Printf("getting data with key %s\n", key)

	if val, ok := m.Index[key]; ok {
		dataFile := m.fileWriter.dataFile

		// Calculer la taille exacte des données à lire
		size := val.end - val.start
		data := make([]byte, size)

		// Utiliser ReadAt pour lire les données
		_, err := dataFile.ReadAt(data, val.start)
		if err != nil {
			if err == io.EOF {
				// Gérer EOF de manière appropriée
				return "", fmt.Errorf("unexpected EOF: %v", err)
			}
			return "", fmt.Errorf("error reading file: %v", err)
		}

		// Pas besoin de découper data, car nous avons déjà la taille exacte
		unpackedData := make(map[string]interface{})
		err = msgpack.Unmarshal(data, &unpackedData)
		if err != nil {
			return "", fmt.Errorf("error unmarshalling data: %v", err)
		}
		// Retourner les données sous forme de chaîne JSON
		jsonData, err := json.Marshal(unpackedData)
		if err != nil {
			return "", fmt.Errorf("error marshalling data: %v", err)
		}

		return string(jsonData), nil
	}

	return "", fmt.Errorf("key not found")
}

func (m *Manager) DeleteData(key string) {
	fmt.Printf("removing data with key %s\n", key)
	// remove data from index
	delete(m.Index, key)
	// delete data from disk
	m.deleteData(key)
}

func (m *Manager) deleteData(key string) error {
	if val, ok := m.Index[key]; ok {
		// 1. Supprimer l'entrée de l'index en mémoire
		delete(m.Index, key)

		// 2. Marquer l'espace comme libre dans le fichier de données
		dataFile := m.fileWriter.dataFile
		emptyData := make([]byte, val.end-val.start)
		_, err := dataFile.WriteAt(emptyData, val.start)
		if err != nil {
			return fmt.Errorf("error writing empty data: %v", err)
		}

		// 3. Mettre à jour le fichier d'index
		return m.rewriteIndexFile(key)
	}
	return fmt.Errorf("key not found")
}

func (m *Manager) rewriteIndexFile(key string) error {
	idxFile := m.fileWriter.idxFile

	// Créer un nouveau fichier d'index temporaire
	tmpIdxFile, err := os.Create(fmt.Sprintf("%s/tmp.idx", m.Path))
	if err != nil {
		return fmt.Errorf("error creating temporary index file: %v", err)
	}
	defer tmpIdxFile.Close()

	// Copier les entrées valides de l'index actuel vers le fichier temporaire
	for k, v := range m.Index {
		if k == key {
			continue
		}
		_, err := fmt.Fprintf(tmpIdxFile, "%s,%d,%d\n", k, v.start, v.end)
		if err != nil {
			return fmt.Errorf("error writing to temporary index file: %v", err)
		}
	}

	// Fermer le fichier d'index actuel
	err = idxFile.Close()
	if err != nil {
		return fmt.Errorf("error closing index file: %v", err)
	}

	// Supprimer l'ancien fichier d'index
	err = os.Remove(fmt.Sprintf("%s/a.idx", m.Path))
	if err != nil {
		return fmt.Errorf("error removing old index file: %v", err)
	}

	// Renommer le fichier temporaire en fichier d'index actuel
	err = os.Rename(fmt.Sprintf("%s/tmp.idx", m.Path), fmt.Sprintf("%s/a.idx", m.Path))
	if err != nil {
		return fmt.Errorf("error renaming temporary index file: %v", err)
	}

	// Ouvrir le nouveau fichier d'index
	idxFile, err = os.OpenFile(fmt.Sprintf("%s/a.idx", m.Path), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("error opening new index file: %v", err)
	}

	// Mettre à jour le fichier d'index dans le fileWriter
	m.fileWriter.idxFile = idxFile
}
