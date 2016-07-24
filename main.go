package main

import (
    	"log"
    	"net/url"
    	"net/http"
	"net/http/httputil"
    	"rsc.io/letsencrypt"
)
func main() {
	dst, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
    	http.Handle("/", &httputil.ReverseProxy{Director: httputil.NewSingleHostReverseProxy(dst).Director})

    	var m letsencrypt.Manager
    	if err := m.CacheFile("letsencrypt.cache"); err != nil {
    		log.Fatal(err)
    	}
    	log.Fatal(m.Serve())
}
