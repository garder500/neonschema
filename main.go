package main

import (
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
	go manager.Start()
	for manager.Status() != "ready" {
		time.Sleep(1 * time.Second)
		fmt.Println("Waiting for manager to be ready...")
	}
	manager.AddData("test", map[string]interface{}{
		"username": "garder",
	})
	// let's try reading the data
	data, err := manager.GetData("test")
	if err != nil {
		panic(fmt.Sprintf("Error getting data: %s", err))
	}
	fmt.Println(data)
	manager.DeleteData("test")

	time.Sleep(1 * time.Second)
	manager.Stop()

}
