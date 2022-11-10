package main

import "net/http"

type CORSMiddleware struct{}

func (m *CORSMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, PUT")
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, If-Modified-Since, Spring-Signature, Spring-Version")
		w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Last-Modified, Spring-Signature, Spring-Version")
		next.ServeHTTP(w, r)
	})
}
