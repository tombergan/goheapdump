package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type XInt struct {
	value int
}

type YInt XInt

var (
	responses []*http.Response
	mu        sync.Mutex
	wg        sync.WaitGroup
)

func dorequest(url string, closeBody bool, x XInt, y YInt) {
	fmt.Fprintf(os.Stderr, "dorequest(%s, %v, %#v, %#v\n", url, closeBody, x, y)
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
		go dorequest(url, k%2 == 0, XInt{k + 10}, YInt{k + 20})
	}
	wg.Wait()
	panic("crash")
}
