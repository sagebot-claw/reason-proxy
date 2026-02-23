package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CAConfig holds the loaded certificate and private key
type CAConfig struct {
	CertFile string
	KeyFile  string
	TLSCert  tls.Certificate
}

// LoadOrGenerateCA loads existing CA certs or generates new ones
func LoadOrGenerateCA(certFile, keyFile string) (*CAConfig, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		if err := GenerateCA(certFile, keyFile); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	return &CAConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		TLSCert:  tlsCert,
	}, nil
}

func GenerateCA(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Reason Proxy CA"},
			CommonName:   "Reason Proxy Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * 10 * time.Hour), // 10 years

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil { return err }
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil { return err }
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	
	return nil
}
