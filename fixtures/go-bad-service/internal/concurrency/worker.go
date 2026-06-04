package concurrency

func StartWorker(ch chan string, jobs <-chan string) {
	go func() {
		for job := range jobs {
			ch <- job
		}
	}()
}
