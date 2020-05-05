package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
)

//Funciton to throw an error when the input CLI has missing/wrong parameters
func missingParametersError() {

	fmt.Println("ERROR: Parameters missing!")
	fmt.Println("HELP:")
	fmt.Println("./elg-decrypt <filename of ciphertext> <filename to read secret key>")

}

//Funciton to setup the CLI
func setupCLI() (string, string) {

	if len(os.Args) < 3 {

		missingParametersError()
		os.Exit(1)
	}

	input1 := os.Args[1]
	input2 := os.Args[2]
	return input1, input2

}

//Function to returns the content from the file in string format
func getInputText(inputText string) string {

	file, err := os.Open(inputText)
	if err != nil {
		log.Fatal(err)
	}

	dataBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	text := string(dataBytes)

	return text
}

// Function that return the shared secret Gab = exp(Ga,b) mod p
func calculateSharedSecret(Gb, A, P *big.Int) *big.Int {

	Gab := new(big.Int)
	Gab.Exp(Gb, A, P)

	return Gab
}

// Function that reads the Public Key from the file
func readCiphertext(filePublicKey string) (*big.Int, string) {

	Gb := new(big.Int)

	filePublicKeyText := getInputText(filePublicKey)
	filePublicKeyText = filePublicKeyText[2 : len(filePublicKeyText)-2]
	filePublicKeyTextSplit := strings.Split(filePublicKeyText, ",")
	GbText := filePublicKeyTextSplit[0]
	cipherText := filePublicKeyTextSplit[1]

	Gb.SetString(GbText, 10)

	return Gb, cipherText
}

// Function that reads the Public Key from the file
func getParameters(filePublicKey string) (*big.Int, *big.Int, *big.Int) {

	P := new(big.Int)
	G := new(big.Int)
	Ga := new(big.Int)

	filePublicKeyText := getInputText(filePublicKey)
	filePublicKeyText = filePublicKeyText[2 : len(filePublicKeyText)-2]
	filePublicKeyTextSplit := strings.Split(filePublicKeyText, ",")
	PText := filePublicKeyTextSplit[0]
	GText := filePublicKeyTextSplit[1]
	GaText := filePublicKeyTextSplit[2]

	P.SetString(PText, 10)
	G.SetString(GText, 10)
	Ga.SetString(GaText, 10)

	// fmt.Println("PText: ", PText)
	// fmt.Println("GText: ", GText)
	// fmt.Println("GaText: ", GaText)

	// fmt.Println("P: ", P)
	// fmt.Println("G: ", G)
	// fmt.Println("Ga: ", Ga)
	return P, G, Ga
}

// Funciton that generates Gab
func generateKey(Ga, Gb, Gab *big.Int) []byte {

	var text string

	text = text + fmt.Sprintf("%s", Ga)
	text = text + " "
	text = text + fmt.Sprintf("%s", Gb)
	text = text + " "
	text = text + fmt.Sprintf("%s", Gab)

	byteText := []byte(text)

	hashFunction := sha256.New()
	hashFunction.Write(byteText)
	hashedBytes := hashFunction.Sum(nil)

	return hashedBytes
}

//Funciton to get integer byte array from hexadecimal values
func hexToBytes(hexadecimal string) []byte {

	n := len(hexadecimal)
	var intBytes = make([]byte, int(n/2))

	for i := 0; i < len(intBytes); i++ {
		x, _ := strconv.ParseUint(hexadecimal[0+i*2:2+i*2], 16, 64)
		intBytes[i] = byte(x)
	}

	return intBytes
}

func decryptAESGCM(messageText string, key []byte) string {

	hexNonce := messageText[:32]
	hexCiphertext := messageText[32:]

	nonce := hexToBytes(hexNonce)
	ciphertext := hexToBytes(hexCiphertext)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		panic(err.Error())
	}

	plainText := fmt.Sprintf("%s", plaintext)

	return plainText
}

// Function that calculates Ga = pow(G, A) mod P
func calculateGa(G, A, P *big.Int) *big.Int {

	var Ga = new(big.Int)

	Ga.Exp(G, A, P)

	return Ga
}

func main() {

	fileCipherText, fileSecretKey := setupCLI()

	Gb, ciphertext := readCiphertext(fileCipherText)
	P, G, A := getParameters(fileSecretKey)
	Gab := calculateSharedSecret(Gb, A, P)
	Ga := calculateGa(G, A, P)
	key := generateKey(Ga, Gb, Gab)

	plaintext := decryptAESGCM(ciphertext, key)

	fmt.Println(plaintext)

}
