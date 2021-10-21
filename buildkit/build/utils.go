package build

import (
	"fmt"
	"net/http"
)

func getResolvingURL(urls []string) (string, error) {
	for _, u := range urls {
		res, err := http.Head(u)
		if err != nil {
			continue
		}
		if res.StatusCode == http.StatusOK {
			return u, nil
		}
	}

	return "", fmt.Errorf("kernel not found")
}
