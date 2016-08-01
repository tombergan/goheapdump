package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

var (
	responses []*http.Response
	mu        sync.Mutex
	wg        sync.WaitGroup
)

func dorequest(url string, closeBody bool) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http.Get(%s): %v\n", url, err)
		return
	}
	if closeBody {
		resp.Body.Close()
	}
	fmt.Fprintf(os.Stderr, "http.Get(%s): %v\n", url, resp.Status)
	mu.Lock()
	responses = append(responses, resp)
	mu.Unlock()
	wg.Done()
	time.Sleep(10 * time.Minute)
	fmt.Fprintf(os.Stderr, "http.Get(%s): done: %s\n", url)
}

func main() {
	urls := []string{
		"http://www.yahoo.com/",
		"http://news.yahoo.com/",
		"http://github.com/",
		"http://www.stackoverflow.com/",
		"http://www.amazon.com/",
		"http://www.microsoft.com/",
	}

	for k, url := range urls {
		wg.Add(1)
		go dorequest(url, k%2 == 0)
	}
	wg.Wait()
	debug.WriteHeapDump(1)
}
