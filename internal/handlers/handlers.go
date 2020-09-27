package handlers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/jnovack/release"
)

var tlsVersion = map[uint16]string{
	769: "TLSv1.0",
	770: "TLSv1.1",
	771: "TLSv1.2",
	772: "TLSv1.3",
}

func CertHandler(certificate []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=root.crt")
		w.Write(certificate)
	}
}

func RootHandler(w http.ResponseWriter, req *http.Request) {
	u, _ := url.Parse(req.URL.String())
	queryParams := u.Query()

	wait := queryParams.Get("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}

	w.Header().Set("Cache-Control", "must-validate")

	hostname, _ := os.Hostname()
	fmt.Fprintln(w, "HOSTNAME:", hostname)

	fmt.Fprintln(w, "BUILD_VERSION:", release.Version)
	fmt.Fprintln(w, "BUILD_COMMIT:", release.Revision)
	fmt.Fprintln(w, "BUILD_RFC3339:", release.BuildRFC3339)

	fmt.Fprintln(w, "TIMESTAMP:", time.Now().Format(time.RFC3339Nano))

	fmt.Fprintln(w, "PROTOCOL:", req.Proto)

	fmt.Fprintln(w, "TLS_CIPHERSUITE:", tls.CipherSuiteName(req.TLS.CipherSuite))
	fmt.Fprintln(w, "TLS_VERSION:", tlsVersion[req.TLS.Version])
}

// Health Check

type healthState struct {
	StatusCode int
}

var currentHealthState = healthState{204}
var mutexHealthState = &sync.RWMutex{}

func HealthHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		var statusCode int
		err := json.NewDecoder(req.Body).Decode(&statusCode)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		} else {
			fmt.Printf("Update health check status code [%d]\n", statusCode)
			mutexHealthState.Lock()
			defer mutexHealthState.Unlock()
			currentHealthState.StatusCode = statusCode
		}
	} else {
		mutexHealthState.RLock()
		defer mutexHealthState.RUnlock()
		w.WriteHeader(currentHealthState.StatusCode)
	}
}
