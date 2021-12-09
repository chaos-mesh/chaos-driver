package build

import (
	"fmt"
	"net/http"
	"sync"
)

func getResolvingURLS(urls []string) ([]string, error) {
	ret := []string{}
	urlsLock := sync.Mutex{}

	wg := sync.WaitGroup{}

	for _, u := range urls {
		u := u

		wg.Add(1)

		go func() {
			res, err := http.Head(u)
			if err != nil {
				return
			}
			if res.StatusCode == http.StatusOK {
				urlsLock.Lock()
				defer urlsLock.Unlock()

				ret = append(ret, u)
			}

			wg.Done()
		}()
	}

	wg.Wait()

	if len(ret) == 0 {
		return nil, fmt.Errorf("no valid URLs found")
	}
	return ret, nil
}
