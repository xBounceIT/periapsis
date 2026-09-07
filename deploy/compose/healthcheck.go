// Command healthcheck performs a bounded HTTP liveness probe for shell-free images.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--print-uid" {
		fmt.Println(os.Getuid())
		return
	}
	if len(os.Args) != 2 && len(os.Args) != 3 {
		os.Exit(2)
	}
	probeTimeout := 2 * time.Second
	if len(os.Args) == 3 {
		var err error
		probeTimeout, err = parseProbeTimeout(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, os.Args[1], nil)
	if err != nil {
		os.Exit(2)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
			Proxy:       nil,
		},
	}

	response, err := client.Do(request)
	if err != nil {
		os.Exit(1)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		os.Exit(1)
	}
}

func parseProbeTimeout(value string) (time.Duration, error) {
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 || timeout > time.Minute {
		return 0, errors.New("probe timeout must be positive and at most one minute")
	}
	return timeout, nil
}
