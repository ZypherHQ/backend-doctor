package retry

import "net/http"

func Forever(url string) {
	for {
		_, _ = http.Get(url)
	}
}
