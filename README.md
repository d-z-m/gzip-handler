# gzip-handler
Minimal `http.Handler` middlewware that defends against [BREACH](https://breachattack.com/) by adding [Heal the BREACH](https://ieeexplore.ieee.org/document/9754554) style mitigations to the response written by the `http.ResponseWriter`.


# Installing
`go get golang.unexpl0.red/gzip-handler`




# Using
```go
package main

import (
	"log"
	"net/http"

	gz "golang.unexpl0.red/gzip-handler"
)

func main() {
	log.Fatal(http.ListenAndServe(":8080", gz.Handler(http.FileServer(http.Dir("./")))))
}
```
