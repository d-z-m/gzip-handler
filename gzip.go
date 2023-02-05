package gzipHandler

import (
        "net/http"
        "compress/gzip"
        "io/ioutil"
        "strings"
        "sync"
        "io"
)

var pool = sync.Pool {
        New: func() interface{} {
                w := gzip.NewWriter(ioutil.Discard)
                return w
        },
}

type gzipResponseWriter struct {
        io.Writer
        http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
        w.Header().Del("Content-Length")
        w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
        return w.Writer.Write(b)
}

func Gzip(h http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                        h.ServeHTTP(w, r)
                        return
                }

                w.Header().Set("Content-Encoding", "gzip")

                gzw := pool.Get().(*gzip.Writer)
                defer pool.Put(gzw)

                gzw.Reset(w)
                defer gz.Close()

		// add Heal-the-BREACH(https://ieeexplore.ieee.org/document/9754554) style mitigation for compresison-based attacks against HTTP
		// while this technique is effectively just adding noise to the channel, it is thought that HTB effectively mitigates BREACH,
		// as it increases the difficulty of the attack by more than 2 orders of magnitude.

                h.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gzw}, r)
        })
}
