package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"github.com/cjlapao/common-go/log"
	"software.sslmate.com/src/go-pkcs12"
)

var logger = log.Get()

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
var policy1 = asn1.ObjectIdentifier{1, 2, 4, 5}
var policy2 = asn1.ObjectIdentifier{1, 1, 3, 4}

// Keys
var ServerAuthentication = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
var ClientAuthentication = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
var CodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
var SecureEmail = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
var TimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
var OCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
var MicrosoftTrustListSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}
var EncryptingFileSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}

var policy3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 5, 2}
var policy4 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 5, 3}
var policy5 = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
var policy6 = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}

var rootPolicy3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 5, 3, 2}
var rootPolicy4 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 5, 3, 3}

type GeneratedCertificate interface {
}

func generateCertificate(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}

func generateCertificateRequest(certificate *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:            certificate.Subject,
		SignatureAlgorithm: certificate.SignatureAlgorithm,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)

	if err != nil {
		return nil, err
	}

	b := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	csrPem := pem.EncodeToMemory(&b)

	return csrPem, nil
}

func generatePemPrivateKey(privateKey *rsa.PrivateKey) []byte {

	b := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateKeyPem := pem.EncodeToMemory(&b)

	return privateKeyPem
}

func generateSerialNumber() *big.Int {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return big.NewInt(1)
	}

	return serialNumber
}

func generateSubjectKeyId(privateKey *rsa.PrivateKey) ([]byte, error) {
	publicKeyBytes, err := asn1.Marshal(*privateKey.Public().(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	subjectKeyId := sha1.Sum(publicKeyBytes)

	return subjectKeyId[:], nil
}

func generatePfx(certificate *x509.Certificate, privateKey *rsa.PrivateKey, password string) ([]byte, error) {
	pfxBytes, err := pkcs12.Encode(rand.Reader, privateKey, certificate, []*x509.Certificate{}, password)

	if err != nil {
		return nil, err
	}

	// see if pfxBytes valid
	_, _, _, err = pkcs12.DecodeChain(pfxBytes, password)
	if err != nil {
		return nil, err
	}

	return pfxBytes, nil
}
