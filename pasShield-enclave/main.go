package main

import (
    "fmt"
    "net"
    "os"
    "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

const (
    CONN_HOST = "localhost"
    CONN_PORT = "8080"
    CONN_TYPE = "tcp"
)

func main() {

    // Create certificate and a report that includes the certificate's hash.
	cert, priv := createCertificate()
	hash := sha256.Sum256(cert)
	report, err := enclave.GetRemoteReport(hash[:])
	if err != nil {
		fmt.Println(err)
	}

    tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

    // Create TCP server.
    // Listen for incoming connections.
    l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        os.Exit(1)
    }

    


    listener, err := tls.Listen("tcp", "0.0.0.0:8080", tlsCfg)
    if err != nil {
        log.Fatal(err)
    }

    defer listener.Close()
    fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
    for {
        // Listen for an incoming connection.
        conn, err := l.Accept()
        if err != nil {
            fmt.Println("Error accepting: ", err.Error())
            os.Exit(1)
        }
        // Handle connections in a new goroutine.
        go handleRequest(conn)
    }
}   

// Handles incoming requests.
func handleRequest(conn net.Conn) {
    // Make a buffer to hold incoming data.
    buf := make([]byte, 1024)
    // Read the incoming connection into the buffer.
    reqLen, err := conn.Read(buf)
    fmt.Println(reqLen)
    if err != nil {
        fmt.Println("Error reading:", err.Error())
    }
    // Send a response back to person contacting us.
    conn.Write([]byte("Message received."))
    // Close the connection when you're done with it.
    conn.Close()
}


func createCertificate() ([]byte, crypto.PrivateKey) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: "localhost"},
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	return cert, priv
}

func main() {
	// Create certificate and a report that includes the certificate's hash.
	cert, priv := createCertificate()
	hash := sha256.Sum256(cert)
	report, err := enclave.GetRemoteReport(hash[:])
	if err != nil {
		fmt.Println(err)
	}

	// Create HTTPS server.

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) { w.Write(cert) })
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) { w.Write(report) })
	http.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%v sent secret %v\n", r.RemoteAddr, r.URL.Query()["s"])
	})

	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

	server := http.Server{Addr: "0.0.0.0:8080", TLSConfig: &tlsCfg}

	fmt.Println("listening ...")
	err = server.ListenAndServeTLS("", "")
	fmt.Println(err)
}