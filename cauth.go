package ifritcert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	errNoAddr           = errors.New("No network address provided in cert request.")
	errNoPort           = errors.New("No port number specified in config.")
	errNoCertFilepath   = errors.New("Tried to save public group certificates with no filepath set in config.")
	errNoKeyFilepath    = errors.New("Tried to save private key with no filepath set in config.")
	errInvalidBootNodes = errors.New("Number of boot nodes needs to be greater than zero.")
	errInvalidNumRings  = errors.New("Number of rings needs to be greater than zero.")
	errPortNotSet       = errors.New("Port number is not set")

	RingNumberOid asn1.ObjectIdentifier = []int{2, 5, 13, 37}
)

type Ca struct {
	privKey *rsa.PrivateKey
	pubKey  crypto.PublicKey

	path        string
	keyFilePath string

	groups []*group
}

type group struct {
	knownCerts      []*x509.Certificate
	knownCertsMutex sync.RWMutex

	existingIds map[string]bool
	idMutex     sync.RWMutex

	groupCert *x509.Certificate

	bootNodes     uint32
	currBootNodes uint32

	numRings uint32
}

// LoadCa initializes a CA from a file path
func LoadCa(path string, numBootNodes, numRings uint32) (*Ca, error) {
	if numBootNodes < 1 {
		return nil, errInvalidBootNodes
	}

	if numRings < 1 {
		return nil, errInvalidNumRings
	}
	keyPath := filepath.Join(path, "key.pem")

	fp, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// Load private key
	keyBlock, _ := pem.Decode(fp)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	if err != nil {
		return nil, err
	}

	c := &Ca{
		privKey:     key,
		pubKey:      key.Public(),
		path:        path,
		keyFilePath: "key.pem",
	}

	// Load group certificates
	dirEntries, err := filepath.Glob(filepath.Join(path, "*"))
	if err != nil {
		return nil, err
	}

	groupDirectories := make([]string, 0)

	// Find all group directories
	for _, d := range dirEntries {
		if d == filepath.Join(path, c.keyFilePath) {
			continue
		}

		// Group certificates
		if err := filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				groupDirectories = append(groupDirectories, info.Name())
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// Load all certs in all group directories
	for _, groupDir := range groupDirectories {
		g := &group{
			knownCerts:  make([]*x509.Certificate, numBootNodes),
			bootNodes:   numBootNodes,
			numRings:    numRings,
			existingIds: make(map[string]bool),
		}

		files, err := ioutil.ReadDir(filepath.Join(path, groupDir))
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			if file.Name() == "ca-cert.pem" {

				// Read group certificate
				fp, err := ioutil.ReadFile(filepath.Join(path, groupDir, file.Name()))
				if err != nil {
					return nil, err
				}
				certBlock, _ := pem.Decode(fp)
				cert, err := x509.ParseCertificate(certBlock.Bytes)
				if err != nil {
					return nil, err
				}

				g.groupCert = cert

				// Search for number of rings extension
				for _, ext := range cert.Extensions {
					if ext.Id.Equal(RingNumberOid) {
						g.numRings = binary.LittleEndian.Uint32(ext.Value)
						break
					}
				}

				// Add group object to CA
				log.Info("Reloaded group certificate with serial id ", g.groupCert.SerialNumber.String())
				log.Info("Number of rings in this group is ", g.numRings)
			}
		}

		c.groups = append(c.groups, g)

		if err := g.loadCertificates(filepath.Join(path, groupDir)); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Create and returns  a new certificate authority instance.
// Generates a private/public keypair for internal use.
func NewCa(path string) (*Ca, error) {
	privKey, err := genRSAKeys()
	if err != nil {
		return nil, err
	}

	if err := os.Mkdir(path, 0755); err != nil {
		return nil, err
	}

	c := &Ca{
		privKey:     privKey,
		pubKey:      privKey.Public(),
		path:        path,
		keyFilePath: "key.pem",
	}

	return c, nil
}

// SavePrivateKey writes the CA private key to the given io object.
func (c *Ca) SavePrivateKey() error {
	if c.keyFilePath == "" {
		return errNoKeyFilepath
	}

	p := filepath.Join(c.path, c.keyFilePath)

	f, err := os.Create(p)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	b := x509.MarshalPKCS1PrivateKey(c.privKey)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	}

	return pem.Encode(f, block)
}

func (c *Ca) SaveCertificate() error {
	for _, g := range c.groups {
		p := fmt.Sprintf("%s/g-%s", c.path, g.groupCert.SerialNumber)
		if err := os.MkdirAll(p, 0755); err != nil {
			return err
		}

		p = fmt.Sprintf("%s/g-%s/ca-cert.pem", c.path, g.groupCert.SerialNumber)

		f, err := os.Create(p)
		if err != nil {
			return err
		}

		b := g.groupCert.Raw

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		}
		err = pem.Encode(f, block)
		if err != nil {
			return err
		}

		certDirPath := fmt.Sprintf("%s/g-%s", c.path, g.groupCert.SerialNumber)
		if err := g.saveCertificates(certDirPath); err != nil {
			return err
		}
	}

	return nil
}

func (g *group) saveCertificates(path string) error {
	for _, c := range g.knownCerts {
		if c != nil {
			p := filepath.Join(path, fmt.Sprintf("g-%s.pem", c.SerialNumber))

			f, err := os.Create(p)
			if err != nil {
				return err
			}

			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			}
			if err = pem.Encode(f, block); err != nil {
				return err
			}
		}
	}

	return nil
}

func (g *group) loadCertificates(path string) error {
	groupCertsPaths, err := filepath.Glob(filepath.Join(path, "g-*.pem"))
	if err != nil {
		return err
	}

	for _, certFile := range groupCertsPaths {
		fp, err := ioutil.ReadFile(certFile)
		if err != nil {
			return err
		}
		certBlock, _ := pem.Decode(fp)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}

		g.addKnownCert(cert)
	}

	return nil
}

func (c *Ca) NewGroup(ringNum, bootNodes uint32) error {
	serialNumber, err := genSerialNumber()
	if err != nil {
		log.Error(err.Error())
		return err
	}

	ringBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ringBytes[0:], ringNum)

	ext := pkix.Extension{
		Id:       RingNumberOid,
		Critical: false,
		Value:    ringBytes,
	}

	caCert := &x509.Certificate{
		SerialNumber:          serialNumber,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().AddDate(-10, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		PublicKey:             c.pubKey,
		ExtraExtensions:       []pkix.Extension{ext},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	gCert, err := x509.CreateCertificate(rand.Reader, caCert, caCert, c.pubKey, c.privKey)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	cert, err := x509.ParseCertificate(gCert)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	g := &group{
		groupCert:   cert,
		numRings:    ringNum,
		knownCerts:  make([]*x509.Certificate, bootNodes),
		bootNodes:   bootNodes,
		existingIds: make(map[string]bool),
	}

	c.groups = append(c.groups, g)

	log.Info("Created a new CA group certificate")

	return nil
}

func genRSAKeys() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (c *Ca) GetCertificateSet(req []byte) ([]byte, error) {
	reqCert, err := x509.ParseCertificateRequest(req)
	if err != nil {
		return nil, err
	}

	g := c.groups[0]

	log.Infof("Generating a new certificate set for hostnames %s ...", reqCert.DNSNames)

	//No idea what this is
	//var oidExtensionBasicConstraints = []int{2, 5, 29, 19}
	//var oidExtensionExtendedKeyUsage = []int{2, 5, 29, 37}
	//var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

	ringBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ringBytes[0:], g.numRings)

	ext := pkix.Extension{
		Id:       []int{2, 5, 13, 37},
		Critical: false,
		Value:    ringBytes,
	}

	serialNumber, err := genSerialNumber()
	if err != nil {
		return nil, err
	}

	id := g.genId()

	newCert := &x509.Certificate{
		SerialNumber:    serialNumber,
		SubjectKeyId:    id,
		Subject:         reqCert.Subject,
		NotBefore:       time.Now().AddDate(-10, 0, 0),
		NotAfter:        time.Now().AddDate(10, 0, 0),
		ExtraExtensions: []pkix.Extension{ext},
		PublicKey:       reqCert.PublicKey,
		//IPAddresses:     []net.IP{ipAddr.IP},
		DNSNames:    reqCert.DNSNames,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, newCert, g.groupCert, reqCert.PublicKey, c.privKey)
	if err != nil {
		return nil, err
	}

	knownCert, err := x509.ParseCertificate(signedCert)
	if err != nil {
		return nil, err
	}
	trusted := g.addKnownCert(knownCert)

	resp := certResponse{
		OwnCert:    signedCert,
		KnownCerts: g.getTrustedNodes(),
		CaCert:     g.groupCert.Raw,
		Trusted:    trusted,
	}

	log.Infof("Including %d known certificates in response to %s ...", len(resp.KnownCerts), reqCert.DNSNames)

	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(resp); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (g *group) addKnownCert(new *x509.Certificate) bool {
	g.knownCertsMutex.Lock()
	defer g.knownCertsMutex.Unlock()

	if g.currBootNodes < g.bootNodes {
		g.knownCerts[g.currBootNodes] = new
	}

	g.currBootNodes++

	return g.currBootNodes <= g.bootNodes
}

func (g *group) getTrustedNodes() [][]byte {
	g.knownCertsMutex.RLock()
	defer g.knownCertsMutex.RUnlock()

	var ret [][]byte
	var certs []*x509.Certificate

	if g.currBootNodes >= g.bootNodes {
		certs = make([]*x509.Certificate, g.bootNodes)
		copy(certs, g.knownCerts)
	} else {
		certs = make([]*x509.Certificate, g.currBootNodes)
		copy(certs, g.knownCerts[:g.currBootNodes])
	}

	for _, c := range certs {
		ret = append(ret, c.Raw)
	}

	return ret
}

func (g *group) genId() []byte {
	g.idMutex.Lock()
	defer g.idMutex.Unlock()

	nonce := make([]byte, 32)

	for {
		_, err := rand.Read(nonce)
		if err != nil {
			log.Error(err.Error())
			continue
		}

		key := string(nonce)

		if _, ok := g.existingIds[key]; !ok {
			g.existingIds[key] = true
			break
		}
	}
	return nonce
}

func genSerialNumber() (*big.Int, error) {
	sLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, sLimit)
	if err != nil {
		return nil, err
	}

	return s, nil
}
