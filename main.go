package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"time"
)

//yas3r@linux:~/Desktop/hashcat-5.1.0$ ./hashcat64.bin -a 3 -m 0 -1 ?l -2 ?d --stdout 1?1?1?1?1?1?l > ~/Desktop/pass.txt

var (
	salt  string = "f789bbc328a3d1a3"
	path2 string = "/home/yas3r/Desktop/pass.txt"
)

func main() {
	readLine(path2)
}

func readLine(path string) {
	inFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err.Error() + `: ` + path)
		return
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		pass := scanner.Text() // the line
		word := fmt.Sprintf("%s%s", salt, pass)
		hashed := GetMD5Hash(word)
		fmt.Printf("[+] %s: %s\n", word, hashed)
		match, _ := regexp.MatchString("^0e[0-9]{30}", hashed)
		if match {
			fmt.Printf("[+] Found it: %s", pass)
			break
		}

	}
}

var src = rand.NewSource(time.Now().UnixNano())

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
