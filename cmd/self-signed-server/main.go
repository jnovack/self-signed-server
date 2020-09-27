package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jnovack/release"
	"github.com/jnovack/self-signed-server/internal/handlers"
	"github.com/jnovack/self-signed-server/pkg/certsign"
)

const (
	httpPort  = "8080"
	httpsPort = "8443"
)

func main() {
	fmt.Println(release.Info())

	hostname, err := os.Hostname()

	values := pkix.Name{
		Organization: []string{"ACME Company"},
	}
	// Root CA
	rootCA, err := certsign.GenerateRoot(values)
	if err != nil {
		log.Fatal(err)
	}

	// Intermediate CA
	svrCA, err := certsign.GenerateIntermediate(values, rootCA)
	if err != nil {
		log.Fatal(err)
	}

	// Server Certificate
	name := fmt.Sprintf("%s.local", hostname[:strings.IndexByte(hostname, '.')])
	server, err := certsign.GenerateServer(values, svrCA, []string{name, hostname})
	if err != nil {
		log.Fatal(err)
	}

	// Main
	httpMux := http.NewServeMux()
	httpMux.Handle("/", handlers.CertHandler(rootCA.PublicBytes))
	go http.ListenAndServe(":"+httpPort, httpMux)

	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", handlers.RootHandler)
	httpsMux.HandleFunc("/health", handlers.HealthHandler)

	// Generate a key pair from your pem-encoded cert and key ([]byte).
	// https://stackoverflow.com/a/47857805/2061684
	allCerts := append(append(server.PublicBytes, svrCA.PublicBytes...), rootCA.PublicBytes...)
	cert, err := tls.X509KeyPair(allCerts, server.PrivateBytes)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsServer := http.Server{
		Handler:   httpsMux,
		Addr:      ":" + httpsPort,
		TLSConfig: tlsConfig,
	}

	err = tlsServer.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}

}
