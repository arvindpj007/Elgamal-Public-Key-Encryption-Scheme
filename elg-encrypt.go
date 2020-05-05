package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
)

//Funciton to throw an error when the input CLI has missing/wrong parameters
func missingParametersError() {

	fmt.Println("ERROR: Parameters missing!")
	fmt.Println("HELP:")
	fmt.Println("./elg-encrypt <message text as a string with quotes> <filename of public key> <filename of ciphertext>")

}

//Funciton to setup the CLI
func setupCLI() (string, string, string) {

	if len(os.Args) < 4 {

		missingParametersError()
		os.Exit(1)
	}

	input1 := os.Args[1]
	input2 := os.Args[2]
	input3 := os.Args[3]
	return input1, input2, input3

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

// Function to write the text content into the output file
func setOutputText(text, output string) {

	var _, err = os.Stat(output)

	// Delete file if exists
	if os.IsExist(err) {

		err = os.Remove(output)
		if err != nil {
			log.Fatal(err)
			fmt.Println("ERROR: cannot open: ", err)
		}

	}

	// Create file
	file, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	// Open file in append mode
	file, err = os.OpenFile(output, os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	// Write content in file
	l, err := file.WriteString(text)
	if err != nil {
		fmt.Println("ERROR: cannot write", err)
		file.Close()
		return
	}
	if l < 0 {

	}
	// fmt.Println(l, "bits written successfully to the file", output)
	file.Sync()
	file.Close()
}

// Function that outputs formatted text from the provided integer inputs
func formatOutputText(Gb *big.Int, ciphertext string) string {

	var text string

	text = "( "
	text = text + fmt.Sprintf("%s", Gb)
	text = text + ","
	text = text + fmt.Sprintf("%s", ciphertext)
	text = text + " )"

	return text
}

// Function that generates B and also Gb = G power B mod P
func getBandGb(P, G *big.Int) (*big.Int, *big.Int) {

	var err error

	B := new(big.Int).SetInt64(0)
	Gb := new(big.Int).SetInt64(0)
	zero := new(big.Int).SetInt64(0)
	two := new(big.Int).SetInt64(2)
	one024 := new(big.Int).SetInt64(1024)
	maxInt := new(big.Int).SetInt64(0)

	checkB := true

	// MAX integer
	maxInt.Exp(two, one024, nil)

	B, err = rand.Int(rand.Reader, maxInt)

	if err != nil {
		fmt.Println("error:", err)
		os.Exit(0)
	}

	for checkB {

		if B.Cmp(zero) == 0 {
			continue
		}

		B.Mod(B, P)

		if B.Cmp(zero) == 0 {
			continue
		}

		if B.Cmp(G) == 0 {
			continue
		}

		checkB = false

	}

	Gb.Exp(G, B, P)

	// fmt.Println("Gb:", G)

	return B, Gb
}

// Function that return the shared secret Gab = exp(Ga,b) mod p
func calculateSharedSecret(Ga, B, P *big.Int) *big.Int {

	Gab := new(big.Int)
	Gab.Exp(Ga, B, P)

	return Gab
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

// Function that outputs formatted text from the provided integer inputs
func getTextFromInts(Gb *big.Int, ciphertext string) string {

	var text string

	text = "( "
	text = text + fmt.Sprintf("%s", Gb)
	text = text + ","
	text = text + ciphertext
	text = text + " )"

	return text
}

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

func encryptAESGCM(messageText string, key []byte) string {

	plaintext := []byte(messageText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	hexCiphertext := fmt.Sprintf("%x", ciphertext)
	hexNonce := fmt.Sprintf("%x", nonce)
	hexCompleteCipher := hexNonce + hexCiphertext

	// fmt.Println("Nonce: ", hexNonce)
	// fmt.Println("Nonce: ", hexCiphertext)

	// fmt.Println("Nonce: ", nonce)
	// fmt.Println("Nonce: ", ciphertext)
	return hexCompleteCipher
}

func main() {

	messageText, filePublicKey, fileCipher := setupCLI()

	P, G, Ga := getParameters(filePublicKey)
	B, Gb := getBandGb(P, G)
	Gab := calculateSharedSecret(Ga, B, P)
	key := generateKey(Ga, Gb, Gab)

	ciphertext := encryptAESGCM(messageText, key)

	text := getTextFromInts(Gb, ciphertext)

	// println(text, fileCipher)
	setOutputText(text, fileCipher)

}
