// Command healthcheck does a single HTTP GET and exits 0 on 2xx, 1 otherwise.
// It exists so distroless (no shell, no wget) services can declare a
// healthcheck that calls a binary already in the image.
//
//	healthcheck http://localhost:8080/healthz
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	url := "http://localhost:8080/healthz"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		os.Exit(0)
	}
	os.Exit(1)
}
