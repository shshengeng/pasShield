package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/square/go-jose.v2/jwt"
)

// serverAddr is the address of the server
const serverAddr = "0.0.0.0:8080"
const saltSize = 16

var token string
var err error

// attestationProviderURL is the URL of the attestation provider
const attestationProviderURL = "https://shareduks.uks.attest.azure.net"

func main() {
	// Create a self signed certificate.
	cert, priv := createCertificate()
	fmt.Println("🆗 Generated Certificate.")

	// Cerate an Azure Attestation Token.
	token, err = enclave.CreateAzureAttestationToken(cert, attestationProviderURL)
	if err != nil {
		panic(err)
	}

	ctx, _ := context.WithCancel(context.Background())
	go checkTokenExpiration(ctx, token, cert)

	fmt.Println("🆗 Created an Microsoft Azure Attestation Token.")

	//create database
	database, err := sql.Open("sqlite3", "./data/password.db")
	if err != nil {
		panic(err)
	}
	//create Table for username,Hmac and salt.
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS Hmac (username varchar(50) PRIMARY KEY, hmac varchar(128), salt BLOB)")
	statement.Exec()
	//create Table for Hmac key
	statement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS Sealed (Hmackey BLOB PRIMARY KEY)")
	statement.Exec()

	//generate a random hmac key
	hmacKey := initialize(database)

	// Create HTTPS server.
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(token)) })
	http.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("📫 %v sent secret %v\n", r.RemoteAddr, r.URL.Query()["s"])
	})

	//register
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Only GET requests are allowed", http.StatusBadRequest)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		pwd := r.FormValue("password")

		fmt.Printf("📫 %v sent username %v\n", r.RemoteAddr, username)
		fmt.Printf("📫 %v sent password %v\n", r.RemoteAddr, pwd)

		// generate a random salt with 10 rounds of complexity
		var salt = generateRandomSalt(saltSize)

		//salting the password
		var salting = salting(pwd, salt)

		//generate hmac
		var hmac = genHmac(salting, hmacKey)

		//insert data into DB
		if err := AddSaltAndHmac(username, hmac, salt, database); err != nil {

			//if the username already exist in DB sent err
			w.Write([]byte(fmt.Sprintf("username %s already exist in DB. Error: %s", username, err.Error())))
			fmt.Println(err)
		} else {
			//test only
			fmt.Println("Salt: ", salt)
			fmt.Println("Salted byte: ", salting)
			fmt.Println("hmac: ", hmac)

			w.Write([]byte(fmt.Sprintf("username: %s", username)))
			w.Write([]byte(fmt.Sprintf("hmac: %s ", hmac)))
			w.Write([]byte(fmt.Sprintf("salt: %s ", salt)))

		}

		/*rows, _ := database.Query("SELECT * FROM Hmac")
		fmt.Println("///////////////////sql code below(test only)/////////////////////////////////")
		for rows.Next() {
			rows.Scan(&username, &hmac, &salt)
			fmt.Println("Username: " , username , "\nHmac: " , hmac , "\nsalt: " , salt , "\n")

		}

		fmt.Println("////////////////////////////////////////////////////")
		fmt.Println("////////////////////////////////////////////////////")
		fmt.Println("////////////////////////////////////////////////////")*/

	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Only GET requests are allowed", http.StatusBadRequest)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		pwd := r.FormValue("password")

		fmt.Printf("📫 %v sent username %v\n", r.RemoteAddr, username)
		fmt.Printf("📫 %v sent password %v\n", r.RemoteAddr, pwd)

		salt, hmac, err := GetSaltAndHmac(username, database)

		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Printf("username is not in the Database")
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("Record not found for username %s: . Error: %s", username, err.Error())))
			}
		} else {
			var salting = salting(pwd, salt)
			fmt.Println("Salted byte: ", salting)
			fmt.Println("hmac from DB: ", hmac)

			var newHmac = genHmac(salting, hmacKey)
			fmt.Println("newhmac: ", newHmac)

			//test only
			//w.Write([]byte(fmt.Sprintf("username: %s", username)))
			//w.Write([]byte(fmt.Sprintf("salting: %s ", salting)))

			if login := compareHMACs(hmac, newHmac); login == true {
				fmt.Println("Verification success")
				//test only
				w.Write([]byte(fmt.Sprintf("Verification success")))
			} else {
				fmt.Println("Verification failure")
				//test only
				w.Write([]byte(fmt.Sprintf("Verification failure")))
			}
		}
	})

	http.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if err := shutdown(hmacKey, database); err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("the state information successfully")
		}
	})

	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

	server := http.Server{Addr: serverAddr, TLSConfig: &tlsCfg}
	fmt.Printf("📎 Token now available under https://%s/token\n", serverAddr)
	fmt.Printf("👂 Listening on https://%s/secret for secrets...\n", serverAddr)
	err = server.ListenAndServeTLS("", "")
	fmt.Println(err)
}

// securely stores the state information outside the enclave when systeam is shutting down.
// input hmacKey return error if exits
func shutdown(hmacKey []byte, database *sql.DB) error {
	var count int
	row := database.QueryRow("SELECT COUNT(*) FROM Sealed")
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("Hmac already exists")
	}
	statement, err := database.Prepare("INSERT INTO Sealed (Hmackey) VALUES (?)")
	if err != nil {
		return err
	}
	defer statement.Close()
	var Seal = Seal_hmacKey(hmacKey)
	_, err = statement.Exec(Seal)
	return err

}

// input hmac from DB and newhmac return bool
// compare HMACs if hmac1 = hmac2 return true
// Otherwise return false
func compareHMACs(hmac1, hmac2 string) bool {
	byteHMAC1 := []byte(hmac1)
	byteHMAC2 := []byte(hmac2)

	// Compare the length of two HMAC values to see if they are equal
	if len(byteHMAC1) != len(byteHMAC2) {
		return false
	}

	// Use the subtle.ConstantTimeCompare() function to compare two HMAC values for equality
	//The ConstantTimeCompare() function compares two byte arrays to see if they are equal
	//but it takes time to execute independent of the size of the two inputs
	//thus preventing side channel attacks.
	return subtle.ConstantTimeCompare(byteHMAC1, byteHMAC2) == 1
}

// Determine if username already exists in the
// database if not add the three inputs to the database
// if it does return an error message
func AddSaltAndHmac(username string, hmac string, salt []byte, database *sql.DB) error {
	var count int
	row := database.QueryRow("SELECT COUNT(*) FROM Hmac WHERE username = ?", username)
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username already exists")
	}
	statement, err := database.Prepare("INSERT INTO Hmac (username, salt, hmac) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer statement.Close()
	_, err = statement.Exec(username, salt, hmac)
	return err
}

// input username return salt and hmac.
// Determine if username already exists in the database
// if not  return an error message if it does return  salt and hmac.
func GetSaltAndHmac(username string, database *sql.DB) ([]byte, string, error) {
	// Execute the selection statement salt and HMAC value
	rows, err := database.Query("SELECT salt, hmac FROM Hmac WHERE username = ?", username)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var salt []byte
	var hmac string

	// Traversing the query results, store the salt and HMAC values into the variable
	for rows.Next() {
		err = rows.Scan(&salt, &hmac)
		if err != nil {
			return nil, "", err
		}
	}

	if salt == nil || hmac == "" {
		return nil, "", sql.ErrNoRows
	}

	return salt, hmac, nil
}

// generate a random hmac key and seal it
func initialize(database *sql.DB) []byte {
	var count int
	row := database.QueryRow("SELECT COUNT(*) FROM Sealed")
	if err := row.Scan(&count); err != nil {
		panic(err)
	}
	if count > 0 {
		// Execute the selection statement Hmackey value
		rows, err := database.Query("SELECT Hmackey FROM Sealed")
		if err != nil {
			panic(err)
		}
		defer rows.Close()
		var Seal []byte

		// Traversing the query results, store the salt and HMAC values into the variable
		for rows.Next() {
			err = rows.Scan(&Seal)
			if err != nil {
				panic(err)
			}
		}
		if Seal == nil {
			panic(err)
		}
		var hmac = Unseal_hmackey(Seal)
		fmt.Printf("init() unSeal hmac key: %s", hmac)
		return hmac
	} else {
		//generate a random hmac key
		random_hmackey, err := GenerateRandomString(128)
		if err != nil {
			panic(err)
		}
		fmt.Println("random_hmackey: ", random_hmackey)
		fmt.Println("*********************************************************************************************************************************************************************************************************")
		var keyBytes = []byte(random_hmackey)
		//seal the hmac key we just generated
		//var Seal =  seal_hmackey(random_hmackey)
		//fmt.Println("seal_hmackey: ", Seal)

		//Seal_statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS Seal (Seal BLOB PRIMARY KEY)")

		return keyBytes
	}
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// seal the Hmac key
func Seal_hmacKey(hmacKey []byte) []byte {
	var additionalData []byte
	seal, err := ecrypto.SealWithUniqueKey(hmacKey, additionalData)

	if err != nil {
		panic(err)
	}
	return seal
}

// Unseal the Hmac key
func Unseal_hmackey(hmacKey []byte) []byte {
	var additionalData []byte
	hmac_key, err := ecrypto.Unseal(hmacKey, additionalData)

	if err != nil {
		panic(err)
	}
	return hmac_key
}

func generateRandomSalt(saltSize int) []byte {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])

	if err != nil {
		panic(err)
	}

	return salt
}

func salting(password string, salt []byte) []byte {
	var passwordBytes = []byte(password)
	passwordBytes = append(passwordBytes, salt...)
	return passwordBytes
}

func genHmac(salted_password []byte, key []byte) string {

	// Create sha-256 hasher
	mac := hmac.New(sha256.New, key)

	// Write password bytes to the hasher
	mac.Write(salted_password)

	// Get the SHA-256 hashed password
	expectedMAC := mac.Sum(nil)

	// Convert the hashed password to a hex string
	var hmacHex = hex.EncodeToString(expectedMAC)

	//return hmacHex
	return hmacHex
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

func checkTokenExpiration(ctx context.Context, tokenString string, cert []byte) {
	//ticker := time.NewTicker(8 * time.Hour)
	ticker := time.NewTicker(481 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Token expiration checker stopped.")
			return
		case <-ticker.C:
			tokenTmp, err := jwt.ParseSigned(tokenString)
			if err != nil {
				fmt.Printf("Failed to parse token: %v\n", err)
				continue
			}

			claims := jwt.Claims{}
			err = tokenTmp.UnsafeClaimsWithoutVerification(&claims)
			if err != nil {
				fmt.Printf("Failed to extract claims: %v\n", err)
				continue
			}

			expirationTime := time.Unix(int64(*claims.Expiry), 0)
			if time.Now().After(expirationTime) {
				// Token expired
				fmt.Println("Token has expired. Renewing token...")

				newToken, err := enclave.CreateAzureAttestationToken(cert, attestationProviderURL)
				if err != nil {
					fmt.Printf("Failed to renew token: %v\n", err)
					continue
				}

				token = newToken
				fmt.Println("Token renewed successfully.")
			} else {
				fmt.Println("Token is still valid.")
			}
		}
	}
}
