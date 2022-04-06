package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/tls-certificate-generator-go/entities"
	"github.com/cjlapao/tls-certificate-generator-go/installer"
)

type X509ServerCertificate struct {
	Name          string
	PrivateKey    *rsa.PrivateKey
	Certificate   *x509.Certificate
	Configuration entities.CertificateConfig
	Pem           []byte
	Csr           []byte
	PrivateKeyPem []byte
}

func (serverCert *X509ServerCertificate) baseFileName() string {
	baseFileName := strings.ReplaceAll(serverCert.Name, " ", "_")
	if baseFileName == "" {
		baseFileName = strings.ReplaceAll(serverCert.Configuration.CommonName, " ", "_")
	}
	return baseFileName
}

func (serverCert *X509ServerCertificate) CertificateFileName() string {
	certificateFileName := serverCert.baseFileName() + ".crt"
	return certificateFileName
}

func (serverCert *X509ServerCertificate) PrivateKeyFileName() string {
	privateKeyFileName := serverCert.baseFileName() + ".key"
	return privateKeyFileName
}

func (serverCert *X509ServerCertificate) CertificateRequestFileName() string {
	certificateRequestFileName := serverCert.baseFileName() + ".csr"
	return certificateRequestFileName
}

func (serverCert *X509ServerCertificate) CertificatePfxFileName() string {
	certificatePfxFileName := serverCert.baseFileName() + ".pfx"
	return certificatePfxFileName
}
func (serverCert *X509ServerCertificate) Generate(intermediateCA *X509IntermediateCertificate, config entities.CertificateConfig) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	logger.Debug("Starting to generate server certificate certificate")

	subject := pkix.Name{
		Country:            []string{config.Country},
		Organization:       []string{config.Organization},
		OrganizationalUnit: []string{config.OrganizationalUnit},
		Province:           []string{config.State},
		Locality:           []string{config.City},
		CommonName:         config.CommonName,
	}

	if config.AdminEmailAddress != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(config.AdminEmailAddress),
				},
			},
		}
	}

	serverCertificateTemplate := x509.Certificate{
		SerialNumber: generateSerialNumber(),
		Subject:      subject,
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().AddDate(config.ExpiresInYears, 0, 0),
		KeyUsage:     x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		IsCA:               false,
		SignatureAlgorithm: config.SignatureAlgorithm.ToX509SignatureAlgorithm(),
		DNSNames:           config.FQDNs,
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			ServerAuthentication, ClientAuthentication,
		},
	}

	if config.FQDNs != nil && len(config.FQDNs) > 0 {
		serverCertificateTemplate.DNSNames = config.FQDNs
	}

	if config.IpAddresses != nil && len(config.IpAddresses) > 0 {
		for _, ip := range config.IpAddresses {
			serverCertificateTemplate.IPAddresses = append(serverCertificateTemplate.IPAddresses, net.ParseIP(ip))
		}
	}

	logger.Debug("Starting to generate private key")
	priv, err := rsa.GenerateKey(rand.Reader, int(config.KeySize))
	if err != nil {
		panic(err)
	}

	subjectKeyId, err := generateSubjectKeyId(priv)
	if err == nil {
		serverCertificateTemplate.SubjectKeyId = subjectKeyId
		serverCertificateTemplate.AuthorityKeyId = subjectKeyId
	}

	intermediateCertificate, intermediatePemCertificate := generateCertificate(&serverCertificateTemplate, intermediateCA.Certificate, &priv.PublicKey, intermediateCA.PrivateKey)
	csr, err := generateCertificateRequest(intermediateCertificate, priv)

	serverCert.PrivateKey = priv
	serverCert.Certificate = intermediateCertificate
	serverCert.Configuration = config
	serverCert.Pem = intermediatePemCertificate
	serverCert.Pem = append(serverCert.Pem, intermediateCA.Pem...)
	serverCert.Csr = csr
	serverCert.PrivateKeyPem = generatePemPrivateKey(priv)

	return intermediateCertificate, intermediatePemCertificate, priv
}

func (serverCert *X509ServerCertificate) LoadFromFile() error {
	return nil
}

func (serverCert *X509ServerCertificate) Parse(certificate string, privateKey string) error {
	if certificate != "" {
		certBlock, _ := pem.Decode([]byte(certificate))
		if certBlock == nil {
			err := errors.New("no valid certificate block found")
			logger.Error("found error while parsing  pem certificate block, err %v", err.Error())
			return err
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			logger.Error("found error while parsing certificate block, err %v", err.Error())
			return err
		}

		serverCert.Certificate = cert
		serverCert.Pem = []byte(certificate)
	}

	if privateKey != "" {
		privBlock, _ := pem.Decode([]byte(privateKey))
		if privBlock == nil {
			err := errors.New("no valid private key block found")
			logger.Error("found error while parsing  pem private key block, err %v", err.Error())
			return err
		}
		priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			logger.Error("found error while parsing private key block, err %v", err.Error())
			return err
		}

		serverCert.PrivateKey = priv
		serverCert.PrivateKeyPem = []byte(privateKey)
	}
	return nil
}

func (serverCert *X509ServerCertificate) SaveToFile() error {
	logger.Debug("Exporting Server Certificate Certificate")
	if helper.FileExists(serverCert.CertificateFileName()) {
		helper.DeleteFile(serverCert.CertificateFileName())
	}

	helper.WriteToFile(string(serverCert.Pem), serverCert.CertificateFileName())

	logger.Debug("Exporting Server Certificate Private Key")
	if helper.FileExists(serverCert.PrivateKeyFileName()) {
		helper.DeleteFile(serverCert.PrivateKeyFileName())
	}

	helper.WriteToFile(string(serverCert.PrivateKeyPem), serverCert.PrivateKeyFileName())

	logger.Debug("Exporting Server Certificate CSR")
	if helper.FileExists(serverCert.CertificateRequestFileName()) {
		helper.DeleteFile(serverCert.CertificateRequestFileName())
	}

	helper.WriteToFile(string(serverCert.Csr), serverCert.CertificateRequestFileName())
	if serverCert.Configuration.Password != "" {
		logger.Debug("Exporting Server Certificate PFX")
		if helper.FileExists(serverCert.CertificatePfxFileName()) {
			helper.DeleteFile(serverCert.CertificatePfxFileName())
		}

		pfx, err := generatePfx(serverCert.Certificate, serverCert.PrivateKey, serverCert.Configuration.Password)
		if err != nil {
			return err
		}

		helper.WriteToFile(string(pfx), serverCert.CertificatePfxFileName())
	}
	return nil
}

func (serverCert *X509ServerCertificate) Install() error {
	instalSvc := installer.Installer{}
	instalSvc.InstallCertificate(serverCert.CertificateFileName(), installer.WebHosting)
	return nil
}
