package entities

type RootCertificate struct {
	Name                     string                     `json:"name" yaml:"name"`
	Config                   *CertificateConfig         `json:"config" yaml:"config"`
	PemCertificate           string                     `json:"PemCertificate" yaml:"PemCertificate"`
	PemPrivateKey            string                     `json:"PemPrivateKey" yaml:"PemPrivateKey"`
	IntermediateCertificates []*IntermediateCertificate `json:"intermediateCertificates" yaml:"intermediateCertificates"`
}

type IntermediateCertificate struct {
	Name           string             `json:"name" yaml:"name"`
	Config         *CertificateConfig `json:"config" yaml:"config"`
	PemCertificate string             `json:"PemCertificate" yaml:"PemCertificate"`
	PemPrivateKey  string             `json:"PemPrivateKey" yaml:"PemPrivateKey"`
	Certificates   []*Certificate     `json:"certificates" yaml:"certificates"`
}

type Certificate struct {
	Name           string             `json:"name" yaml:"name"`
	Config         *CertificateConfig `json:"config" yaml:"config"`
	PemCertificate string             `json:"PemCertificate" yaml:"PemCertificate"`
	PemPrivateKey  string             `json:"PemPrivateKey" yaml:"PemPrivateKey"`
}
