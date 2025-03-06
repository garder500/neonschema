package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/garder500/neonschema/manager"
)

var mgr *manager.Manager

var max = 20000
var waitPeriod time.Duration = 0

func init() {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	manager := manager.NewManager(fmt.Sprintf("%s/data", pwd))
	if err = manager.Start(); err != nil {
		fmt.Println("Failed start:", err)
	}
	mgr = manager
}

func TestWrites(t *testing.T) {
	for i := 0; i < max; i++ {
		dataToAdd := map[string]interface{}{
			"username": fmt.Sprintf("garder%d", i),
		}
		dataToAddJSON, err := json.Marshal(dataToAdd)
		if err != nil {
			panic(fmt.Sprintf("Error marshaling data: %s", err))
		}
		mgr.AddData(fmt.Sprintf("test%d", i), string(dataToAddJSON))
	}
}

func TestReads(t *testing.T) {
	for i := 0; i < max; i++ {
		_, err := mgr.GetData(fmt.Sprintf("test%d", i))
		if err != nil {
			fmt.Println("Error getting data:", err)
		}
	}

	time.Sleep(waitPeriod * time.Second)
}

func TestDeletes(t *testing.T) {
	for i := 0; i < max; i++ {
		mgr.DeleteData(fmt.Sprintf("test%d", i))
	}

	time.Sleep(waitPeriod * time.Second)
}
