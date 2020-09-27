package certsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Cert structure
type Cert struct {
	Certificate x509.Certificate

	Private *pem.Block
	Public  *pem.Block

	PrivateBytes []byte
	PublicBytes  []byte
}

var caTemplate = x509.Certificate{
	IsCA:      true,
	NotBefore: time.Now().UTC(),
	NotAfter:  time.Now().UTC().Add(367 * 24 * time.Hour),

	KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

	BasicConstraintsValid: true,
}

var serverTemplate = x509.Certificate{
	IsCA:      false,
	NotBefore: time.Now().UTC(),
	NotAfter:  time.Now().UTC().Add(367 * 24 * time.Hour),

	KeyUsage: x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
	},
	BasicConstraintsValid: true,
}

var clientTemplate = x509.Certificate{
	IsCA:      false,
	NotBefore: time.Now().UTC(),
	NotAfter:  time.Now().UTC().Add(367 * 24 * time.Hour),

	KeyUsage: x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	},
	BasicConstraintsValid: true,
}

func randomSerialNumber() (*big.Int, *string, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	src := serialNumber.Bytes()
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	lastFour := fmt.Sprintf("%s", strings.ToUpper(string(dst[len(dst)-4:])))

	return serialNumber, &lastFour, nil
}

// GenerateRoot generates a root certificate, returns cert
func GenerateRoot(fields pkix.Name) (*Cert, error) {
	if fields.CommonName == "" {
		fields.CommonName = fields.Organization[0]
	}

	fields.CommonName = fields.CommonName + " Root CA"

	rootCA := caTemplate
	rootCA.Subject = pkix.Name{
		CommonName:   fields.CommonName,
		Organization: fields.Organization,
	}

	cert, err := genCert(&rootCA, nil)
	return cert, err
}

// GenerateIntermediate generates an intermediate certificate, returns cert
func GenerateIntermediate(fields pkix.Name, signCA *Cert) (*Cert, error) {
	if fields.CommonName == "" {
		fields.CommonName = fields.Organization[0]
	}

	fields.CommonName = fields.CommonName + " Intermediate CA"

	intermediateCA := caTemplate
	intermediateCA.Subject = pkix.Name{
		CommonName:   fields.CommonName,
		Organization: fields.Organization,
	}
	intermediateCA.MaxPathLen = 1

	cert, err := genCert(&intermediateCA, signCA)
	return cert, err
}

// GenerateServer generates an server certificate, returns cert
func GenerateServer(fields pkix.Name, signCA *Cert, hosts []string) (*Cert, error) {
	if fields.CommonName == "" {
		fields.CommonName = fields.Organization[0]
	}

	serverCA := caTemplate
	serverCA.Subject = pkix.Name{
		CommonName:   fields.CommonName,
		Organization: fields.Organization,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			serverCA.IPAddresses = append(serverCA.IPAddresses, ip)
		} else {
			serverCA.DNSNames = append(serverCA.DNSNames, host)
		}
	}

	cert, err := genCert(&serverCA, signCA)
	return cert, err
}

// GenerateClient generates an client certificate, returns cert
func GenerateClient(fields pkix.Name, signCA *Cert, hosts []string) (*Cert, error) {
	if fields.CommonName == "" {
		fields.CommonName = fields.Organization[0]
	}

	clientCA := caTemplate
	clientCA.Subject = pkix.Name{
		CommonName:   fields.CommonName,
		Organization: fields.Organization,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			clientCA.IPAddresses = append(clientCA.IPAddresses, ip)
		} else {
			clientCA.DNSNames = append(clientCA.DNSNames, host)
		}
	}

	cert, err := genCert(&clientCA, signCA)
	return cert, err
}

func genCert(child *x509.Certificate, parent *Cert) (*Cert, error) {
	var signingKey interface{}

	// Serial Number
	serialNumber, lastFour, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	// Flex in Serial Number to Certificate
	child.SerialNumber = serialNumber
	child.Subject.CommonName = fmt.Sprintf("%s (%s)", child.Subject.CommonName, *lastFour)
	child.Subject.SerialNumber = serialNumber.String()

	// Generate New Key
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Isolate Signing Key
	if parent == nil {
		parent = new(Cert)
		parent.Certificate = *child
		signingKey = key
	} else {
		signingKey, err = x509.ParsePKCS8PrivateKey(parent.Private.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// Create Certificate
	cert := new(Cert)
	derBytes, err := x509.CreateCertificate(rand.Reader, child, &parent.Certificate, &key.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	cert.Public = &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, cert.Public); err != nil {
		return nil, fmt.Errorf("failed to write data to cert.pem: %s", err)
	}
	cert.PublicBytes = make([]byte, buf.Len())
	copy(cert.PublicBytes, buf.Bytes())
	buf.Reset()

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal ECDSA private key: %v", err)
	}
	cert.Private = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	if err := pem.Encode(buf, cert.Private); err != nil {
		return nil, fmt.Errorf("failed to encode key data: %s", err)
	}
	cert.PrivateBytes = make([]byte, buf.Len())
	copy(cert.PrivateBytes, buf.Bytes())

	cert.Certificate = *child
	return cert, nil
}
