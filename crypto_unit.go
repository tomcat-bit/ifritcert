package ifritcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

var (
	errNoRingNum      = errors.New("No ringnumber present in received certificate")
	errNoHostIp       = errors.New("No ip or hostname present in received identity")
	errNoAddrs        = errors.New("Not enough addresses present in identity")
	errInvlPath       = errors.New("Argument path to load empty")
	errPemDecode      = errors.New("Unable to decode content in given file")
	errNoCryptoPath   = errors.New("Path for crypto resources is empty")
	errNoCa           = errors.New("No address for Certificate Authority")
	errNoConfig       = errors.New("Crypto unit configuration is nil")
	ErrLoadCryptoUnit = errors.New("Could not load crypto unit from disk.")
)

type CryptoUnit struct {
	priv   *ecdsa.PrivateKey
	pk     pkix.Name
	caAddr string

	path       string
	self       *x509.Certificate
	ca         *x509.Certificate
	numRings   uint32
	knownCerts []*x509.Certificate
	trusted    bool
}

type CryptoUnitConfig struct {
	Identity    pkix.Name
	DNSNames    []string
	IPAddresses []string
	Path        string
	cg          certificateGenerator
}

type CertificateSet struct {
	OwnCert    *x509.Certificate
	KnownCerts []*x509.Certificate
	CaCert     *x509.Certificate
	Trusted    bool
}

type certResponse struct {
	OwnCert    []byte
	KnownCerts [][]byte
	CaCert     []byte
	Trusted    bool
}

type certificateGenerator interface {
	GetCertificateSet(req []byte) ([]byte, error)
}

//func NewCu(identity pkix.Name, workingDir string, caAddr string, dnsLabel string) (*CryptoUnit, error) {
func NewCu(config *CryptoUnitConfig, cg certificateGenerator) (*CryptoUnit, error) {
	var extValue []byte

	if config == nil {
		return nil, errNoConfig
	}

	priv, err := genECDSAKeys()
	if err != nil {
		return nil, err
	}

	certs, err := getCertificate(cg, priv, config.Identity, config.DNSNames)
	if err != nil {
		return nil, err
	}

	for _, e := range certs.OwnCert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 13, 37}) {
			extValue = e.Value
		}
	}

	if extValue == nil {
		return nil, errNoRingNum
	}

	numRings := binary.LittleEndian.Uint32(extValue[0:])

	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return nil, err
	}

	return &CryptoUnit{
		ca:         certs.CaCert,
		self:       certs.OwnCert,
		numRings:   numRings,
		path:       config.Path,
		pk:         config.Identity,
		priv:       priv,
		knownCerts: certs.KnownCerts,
		trusted:    certs.Trusted,
	}, nil
}

func LoadCu(config *CryptoUnitConfig) (*CryptoUnit, error) {
	stat, err := os.Stat(config.Path)
	if err != nil || !stat.IsDir() {
		log.Errorf("Path %s is not a valid directory", config.Path)
		return nil, ErrLoadCryptoUnit
	}

	var extValue []byte

	certs, err := loadCertSet(config.Path)
	if err != nil {
		return nil, err
	}

	priv, err := loadPrivKey(config.Path)
	if err != nil {
		return nil, err
	}

	for _, e := range certs.OwnCert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 13, 37}) {
			extValue = e.Value
		}
	}

	if extValue == nil {
		return nil, errNoRingNum
	}

	numRings := binary.LittleEndian.Uint32(extValue[0:])

	return &CryptoUnit{
		ca:         certs.CaCert,
		path:       config.Path,
		self:       certs.OwnCert,
		numRings:   numRings,
		pk:         config.Identity,
		priv:       priv,
		knownCerts: certs.KnownCerts,
		trusted:    certs.Trusted,
	}, nil
}

func (cu *CryptoUnit) Trusted() bool {
	return cu.trusted
}

func (cu *CryptoUnit) Certificate() *x509.Certificate {
	return cu.self
}

func (cu *CryptoUnit) CaCertificate() *x509.Certificate {
	return cu.ca
}

func (cu *CryptoUnit) NumRings() uint32 {
	return cu.numRings
}

func (cu *CryptoUnit) Priv() *ecdsa.PrivateKey {
	return cu.priv
}

func (cu *CryptoUnit) ContactList() []*x509.Certificate {
	ret := make([]*x509.Certificate, 0, len(cu.knownCerts))

	for _, c := range cu.knownCerts {
		ret = append(ret, c)
	}

	return ret
}

func (cu *CryptoUnit) Verify(data, r, s []byte, pub *ecdsa.PublicKey) bool {
	if pub == nil {
		log.Error("Peer had no publicKey")
		return false
	}

	var rInt, sInt big.Int

	b := hashContent(data)

	rInt.SetBytes(r)
	sInt.SetBytes(s)

	return ecdsa.Verify(pub, b, &rInt, &sInt)
}

func (cu *CryptoUnit) Sign(data []byte) ([]byte, []byte, error) {
	hash := hashContent(data)

	r, s, err := ecdsa.Sign(rand.Reader, cu.priv, hash)
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}

func (cu *CryptoUnit) SavePrivateKey() error {
	path := filepath.Join(cu.path, "key.pem")
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(cu.priv)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	err = pem.Encode(f, block)
	if err != nil {
		return err
	}

	return f.Close()
}

func (cu *CryptoUnit) SaveCertificate() error {
	for _, knownCert := range cu.knownCerts {
		fname := filepath.Join(cu.path, fmt.Sprintf("g-%s.pem", knownCert.SerialNumber))
		if err := saveCert(knownCert, fname); err != nil {
			log.Error(err.Error())
		}
	}

	fname := filepath.Join(cu.path, fmt.Sprintf("ca-%s.pem", cu.ca.SerialNumber))
	if err := saveCert(cu.ca, fname); err != nil {
		log.Error(err.Error())
	}

	fname = filepath.Join(cu.path, fmt.Sprintf("self-%s.pem", cu.self.SerialNumber))
	if err := saveCert(cu.self, fname); err != nil {
		log.Error(err.Error())
	}

	return nil
}

func saveCert(cert *x509.Certificate, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	if err := pem.Encode(f, block); err != nil {
		return err
	}

	return f.Close()
}

func loadCertSet(certPath string) (*CertificateSet, error) {
	if certPath == "" {
		return nil, errInvlPath
	}

	matches, err := filepath.Glob(filepath.Join(certPath, "self-*.pem"))
	if err != nil {
		return nil, err
	} else if matches == nil {
		return nil, fmt.Errorf("Storage path '%s' gave no hits on certificates", certPath)
	} else if len(matches) > 1 {
		return nil, fmt.Errorf("Path: '%s' contained more than one private key", certPath)
	}

	selfCert, err := loadCert(matches[0])
	if err != nil {
		return nil, err
	}

	log.Infof("Own certificate loaded from file '%s'", matches[0])

	matches, err = filepath.Glob(filepath.Join(certPath, "g-*.pem"))
	if err != nil {
		return nil, err
	} else if matches == nil {
		return nil, errors.New(fmt.Sprintf("Path '%s' gave no hits on certificates", certPath))
	}

	knownCerts := make([]*x509.Certificate, 0, len(matches))

	for i, path := range matches {
		gCert, err := loadCert(path)
		if err != nil {
			return nil, err
		}

		knownCerts = append(knownCerts, gCert)

		log.Infof("Known certificate #%d loaded on path %s", i+1, path)
	}

	matches, err = filepath.Glob(filepath.Join(certPath, "ca-*.pem"))
	if err != nil {
		return nil, err
	} else if len(matches) > 1 {
		return nil, fmt.Errorf("Path '%s' contains more than CA certificate", certPath)
	}

	caCert, err := loadCert(matches[0])
	if err != nil {
		return nil, err
	}

	log.Infof("CA certificate loaded at path '%s'", matches[0])

	return &CertificateSet{
		OwnCert:    selfCert,
		KnownCerts: knownCerts,
		CaCert:     caCert,
		Trusted:    true,
	}, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	certPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		return nil, errPemDecode
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func loadPrivKey(certPath string) (*ecdsa.PrivateKey, error) {
	if certPath == "" {
		return nil, errInvlPath
	}

	path := filepath.Join(certPath, "key.pem")

	keyPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPem)
	if keyBlock == nil {
		return nil, errPemDecode
	}

	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	log.Infof("Private key loaded from path '%s'", path)

	return privKey, nil
}

func getCertificate(cg certificateGenerator, privKey *ecdsa.PrivateKey, pk pkix.Name, DNSNames []string) (*CertificateSet, error) {
	var certsResp certResponse
	set := &CertificateSet{}

	template := x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            pk,
		DNSNames:           DNSNames,
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, err
	}

	resp, err := cg.GetCertificateSet(certReqBytes)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp, &certsResp); err != nil {
		return nil, err
	}

	set.OwnCert, err = x509.ParseCertificate(certsResp.OwnCert)
	if err != nil {
		return nil, err
	}

	set.CaCert, err = x509.ParseCertificate(certsResp.CaCert)
	if err != nil {
		return nil, err
	}

	for _, b := range certsResp.KnownCerts {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		set.KnownCerts = append(set.KnownCerts, c)
	}

	set.Trusted = certsResp.Trusted

	return set, nil
}

func genId() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

func genECDSAKeys() (*ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func hashContent(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
