package library

import "log"

func MustLoad(ok bool) {
	if !ok {
		log.Fatal("configuration missing")
	}
}
