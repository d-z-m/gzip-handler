package gzip

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

// configurable padding size
const (
	// denotes the maximum padding in bytes that can be applied to a given request
	// 10 is thought to be sufficient against normal attacks, as it increases the
	// amount of requests an attacker must perform(~50k with padding=10, ~5M with
	// padding =100) to get any meaningful signal. This makes any attempt at an attack
	// leveraging BREACH obvious to an IDS/WAF capability, and thus easily blockable.
	// if adding a random value by modular reduction as we are here, this needs to be a power of 2, to avoid modulo bias reducing the uint16
	HTBPaddingSize = 32
)

var padding string

func init() {
	var paddingBuilder strings.Builder
	for i := 0; i < HTBPaddingSize; i++ {
		paddingBuilder.WriteString("A")
	}
	padding = paddingBuilder.String()

	if len(padding) != HTBPaddingSize {
		panic("gzip-handler:::error initializing HTB padding!")
	}
}

var gzipPool = sync.Pool{
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

func Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gzw := gzipPool.Get().(*gzip.Writer)
		defer gzipPool.Put(gzw)

		gzw.Reset(w)
		defer gzw.Close()

		// add Heal-the-BREACH(https://ieeexplore.ieee.org/document/9754554) style mitigation for compresison-based attacks against HTTP
		// while this technique is effectively just adding noise to the channel, it is thought that HTB effectively mitigates BREACH,
		// as it increases the difficulty of the attack by more than 2 orders of magnitude for a padding length of up to 10 bytes.

		gzw.Header.Name = padding[:(randomUint16()%HTBPaddingSize)+1]

		h.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gzw}, r)
	})
}

var paddingBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2)
	},
}

func randomUint16() (n uint16) {
	buf := paddingBufferPool.Get().([]byte)
	defer paddingBufferPool.Put(buf)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	n = binary.BigEndian.Uint16(buf)
	return
}
