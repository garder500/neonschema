package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/garder500/neonschema/manager"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	manager := manager.NewManager(fmt.Sprintf("%s/data", pwd))
	if err := manager.Start(); err != nil {
		fmt.Println("Failed start:", err)
	}

	manager.DeleteData("salut")
	dataToAdd := map[string]interface{}{
		"username": "garder",
	}
	dataToAddJSON, err := json.Marshal(dataToAdd)
	if err != nil {
		panic(fmt.Sprintf("Error marshaling data: %s", err))
	}
	manager.AddData("test", string(dataToAddJSON))
	manager.AddData("garder", string(dataToAddJSON))
	// let's try reading the data
	data, err := manager.GetData("test")
	if err != nil {
		fmt.Println("Error getting data:", err)
	} else {
		fmt.Println(data)
	}
	manager.AddData("salut", string(dataToAddJSON))
	manager.AddData("salut", string("test"))

	manager.DeleteData("garder")
	manager.DeleteData("test")
	// let's try reading the data
	data, err = manager.GetData("test")
	if err != nil {
		fmt.Println("Error getting data:", err)
	} else {
		fmt.Println(data)
	}
	time.Sleep(1 * time.Second)
	manager.Stop()

}
