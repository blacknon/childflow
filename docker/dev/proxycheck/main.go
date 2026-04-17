package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <url>\n", os.Args[0])
		os.Exit(2)
	}

	target := os.Args[1]
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxycheck: failed to build request: %v\n", err)
		os.Exit(1)
	}

	reportProxyEnv()
	reportSelectedProxy(req)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxycheck: request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "proxycheck: response status: %s\n", resp.Status)
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fmt.Fprintf(os.Stderr, "proxycheck: failed to copy response body: %v\n", err)
		os.Exit(1)
	}
}

func reportProxyEnv() {
	keys := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
		"NO_PROXY",
		"no_proxy",
	}

	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			fmt.Fprintf(os.Stderr, "proxycheck: %s=%s\n", key, value)
		}
	}
}

func reportSelectedProxy(req *http.Request) {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxycheck: failed to evaluate proxy environment: %v\n", err)
		return
	}
	if proxyURL == nil {
		fmt.Fprintln(os.Stderr, "proxycheck: no proxy selected")
		return
	}
	fmt.Fprintf(os.Stderr, "proxycheck: selected proxy: %s\n", proxyURL.String())
}
