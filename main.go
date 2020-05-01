package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"
)

// Chain: Root CA -> Intermediate CA Level 1 -> Intermediate CA Level 2 -> End Entity
// Only Root CA will be known in chain, client will supply lvl1, lvl2 and end entity certs
// Server will use Root CA as server certificate

const serverAddress = "0.0.0.0:8000"

var serverListener net.Listener

func main() {
	log.Print("Generating key material...")
	rootKey, rootCert := generateCaCert("Root CA", nil, nil)
	writeCerts("ca-bundle.pem", rootCert)
	// Branch A
	intermA1Key, intermA1Cert := generateCaCert("Intermediate A Level 1", rootCert, rootKey)
	intermA2Key, intermA2Cert := generateCaCert("Intermediate A Level 2", intermA1Cert, intermA1Key)
	clientAKey, clientACert := generateClientCert("Client A", intermA2Cert, intermA2Key)
	writeCerts("client-a-cert.pem", clientACert, intermA2Cert, intermA1Cert, rootCert)
	writeKey("client-a-key.pem", clientAKey)
	// Branch B
	intermB1Key, intermB1Cert := generateCaCert("Intermediate B Level 1", rootCert, rootKey)
	intermB2Key, intermB2Cert := generateCaCert("Intermediate B Level 2", intermB1Cert, intermB1Key)
	clientBKey, clientBCert := generateClientCert("Client A", intermB2Cert, intermB2Key)
	writeCerts("client-b-cert.pem", clientBCert, intermB2Cert, intermB1Cert, rootCert)
	writeKey("client-b-key.pem", clientBKey)

	// Test Go TLS
	//startServer(rootCert, rootKey)
	//connectClient(clientAKey, clientACert, intermA2Cert, intermA1Cert, rootCert)
}

func writeKey(file string, key *rsa.PrivateKey) {
	d, _ := x509.MarshalPKCS8PrivateKey(key)
	ioutil.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: d}), 0777)
}

func writeCerts(file string, certs ...*x509.Certificate) {
	data := new(bytes.Buffer)
	for _, cert := range certs {
		b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		data.Write(b)
	}
	ioutil.WriteFile(file, data.Bytes(), 0777)
}

func startServer(cert *x509.Certificate, key crypto.PrivateKey) {
	log.Print("server: starting...")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	config := tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}},
		ClientCAs: pool,
	}
	config.Rand = rand.Reader
	var err error
	serverListener, err = tls.Listen("tcp", serverAddress, &config)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := serverListener.Accept()
			if err != nil {
				log.Printf("server: accept: %s", err)
				break
			}
			defer conn.Close()
			log.Printf("server: accepted from %s", conn.RemoteAddr())
			printTLSState(conn)
			go handleClient(conn)
		}
	}()
	log.Print("server: started")
}

func printTLSState(conn net.Conn) {
	tlscon := conn.(*tls.Conn)
	state := tlscon.ConnectionState()
	if state.HandshakeComplete {
		log.Printf("server: handshake complete")
		log.Printf("server: client certificate chain:")
		for i, v := range state.PeerCertificates {
			log.Printf(" %d. %s", i+1, v.Subject.String())
		}
	}
}

func connectClient(key crypto.PrivateKey, certs ...*x509.Certificate) {
	log.Print("client: connecting...")
	cert := tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  key,
	}
	for _, c := range certs {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		log.Printf("client: server certificate: %s", v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	_, err = io.WriteString(conn, "Test")
	if err != nil {
		panic(err)
	}
	reply := make([]byte, 256)
	n, _ := conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}

func generateCaCert(cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		PublicKey:             key.PublicKey,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	var data []byte
	var err error
	if ca == nil {
		data, err = x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	} else {
		data, err = x509.CreateCertificate(rand.Reader, &template, ca, key.Public(), caKey)
	}
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		panic(err)
	}
	return key, cert
}

func generateClientCert(cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		PublicKey:    key.PublicKey,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, ca, key.Public(), caKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		panic(err)
	}
	return key, cert
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}
		printTLSState(conn)
		log.Printf("server: conn: echo %q\n", string(buf[:n]))
		n, err = conn.Write(buf[:n])

		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
