package utils

import (
	"errors"
	"os"

	"github.com/vmihailenco/msgpack"
)

func AddToFile(name string, data interface{}, manager *Manager) error {
	b, err := msgpack.Marshal(data)
	if err != nil {
		return err
	}

	f, err := manager.GetFirstHandle()
	if err != nil {
		return err
	}

	// we will create a new idx pointing to the end of the file
	stat, err := f.Stat()
	if err != nil {
		return err
	}

	// write the data to the file
	size, err := f.Write(b)
	if err != nil {
		return err
	}

	// Add IDX
	manager.AddIdx(name, stat.Size(), stat.Size()+int64(size))
	return nil
}

func GetHandleFromIdxName(name string, manager *Manager) (*os.File, *Idx, error) {
	idx, ok := manager.GetIdx(name)
	if !ok {
		return nil, nil, errors.New("idx not found")
	}

	// Get IDX path
	path, ok := manager.GetIdxPath(name)
	if !ok {
		return nil, nil, errors.New("idx path not found")
	}

	f, ok := manager.GetFileHandle(path)
	if !ok {
		return nil, nil, errors.New("file not found")
	}

	return f, &idx, nil
}

func ReadFromFile(name string, manager *Manager) (interface{}, error) {
	f, idx, err := GetHandleFromIdxName(name, manager)
	if err != nil {
		return nil, err
	}

	b := make([]byte, idx.Size())
	_, err = f.ReadAt(b, idx.srt)
	if err != nil {
		return nil, err
	}

	var data interface{}
	err = msgpack.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func RemoveFromFile(name string, manager *Manager) error {
	f, _, err := GetHandleFromIdxName(name, manager)
	if err != nil {
		return err
	}

	// Remove IDX
	delete(manager.idx, name)

	// Remove file if no more idx points to it
	if _, ok := manager.GetIdxPath(name); !ok {
		delete(manager.files, f.Name())
		err = f.Close()
		if err != nil {
			return err
		}
		err = os.Remove(f.Name())
		if err != nil {
			return err
		}
	}

	return nil
}
