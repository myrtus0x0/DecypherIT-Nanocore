package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"unicode"
)

var (
	encryptedStrings []string
	inputFile        string
)

func init() {
	flag.StringVar(&inputFile, "input_file", "", "input file with the  obfsucated nanocore file")
}

func xor(enc []byte, key byte) (string, error) {
	ret := []byte{}

	for i := 0; i < len(enc); i++ {
		temp := enc[i] ^ key
		ret = append(ret, temp)
	}

	return string(ret), nil
}

func xorBrute(encodedStr []byte) (string, error) {
	switch string(encodedStr[0]) {
	case "0":
		// lazy
		return xor(encodedStr, 0)
	case "1":
		return xor(encodedStr, 1)
	case "2":
		return xor(encodedStr, 2)
	case "3":
		return xor(encodedStr, 3)
	case "4":
		return xor(encodedStr, 4)
	}

	return "", errors.New("not a valid nanocore encoding")
}

func file2lines(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return linesFromReader(f)
}

func linesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func decryptStrings(lines []string) ([]string) {
	var re = regexp.MustCompile(`(?m)"\b[0-9A-F]{2,}\b"`)
	modLines := []string{}

	for i, line := range lines {
		matched := false
		tempLine := ""
		tempLine += line
		for _, match := range re.FindAllString(line, -1) {
			matched = true
			cleaned := strings.Replace(match, "\"", "", -1)
			dec, err := hex.DecodeString(cleaned)
			if err != nil {
				modLines = append(modLines, tempLine)
				break
			}

			decodedStr, err := xorBrute(dec)
			if err != nil {
				modLines = append(modLines, tempLine)
				break
			}

			if len(decodedStr) < 2 {
				modLines = append(modLines, tempLine)
				break
			}

			if decodedStr[0:2] == "0x" {
				temp, err := hex.DecodeString(strings.Replace(decodedStr, "0x", "", -1))
				if err != nil {
					modLines = append(modLines, tempLine)
					break
				}
				decodedStr = string(temp)
			}
			if isASCII(decodedStr) {
				tempLine += " ;" + decodedStr
				fmt.Printf("[+] decoded string at line %d: %s\n", i, decodedStr)
			} else {
				tempLine += " ;" + "BINARYCONTENT"			
			}

			modLines = append(modLines, tempLine)
			break
		}
		
		if !matched {
			modLines = append(modLines, tempLine)
		}
	}

	return modLines
}

func removeVars(lines []string) ([]string) {
	getVarName := regexp.MustCompile(`(?m)(Dim|Local|Global Const|Global)\s\$(?P<Name>\w+)\s`)

	modLines := []string{}

	for i, line := range lines {
		// If it is a variable declaration get the variable name
		match := getVarName.FindStringSubmatch(line)
		if len(match) == 0 {
			modLines = append(modLines, line)
			continue
		}

		result := make(map[string]string)

		// turn the regex groups into a map
		for k, name := range getVarName.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[k]
			}
		}
		
		// count the number of occurences in the new file
		occurences := 0
		for _, secondLine := range lines {
			if strings.Contains(secondLine, result["Name"]) {
				occurences++
			}
		}

		// if the variable is used multiple times keep it
		if occurences > 1 {
			modLines = append(modLines, line)
		}
	}

	return modLines
}

func removeFuncs(lines []string) ([]string) {
	var getFuncName = regexp.MustCompile(`(?m)Func\s(?P<Name>\w+)`)
	
	modLines := []string{}

	unusedFuncs := []string{}
	for i, line := range lines {
		// If it is a func declaration get the func name
		match := getFuncName.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}

		result := make(map[string]string)

		// turn the regex groups into a map
		for k, name := range getFuncName.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[k]
			}
		}
		
		// count the number of occurences in the new file
		occurences := 0
		for _, secondLine := range lines {
			if strings.Contains(secondLine, result["Name"]) {
				occurences++
			}
		}

		// if the function is just used once, find it and dont write it to the file 
		if occurences == 1 {
			unusedFuncs = append(unusedFuncs, result["Name"])
		}
	}

	// now that we have all of the unused functions, we need to remove them
	for i := 0; i < len(lines); i++ {
		for _, unusedFunc := range unusedFuncs {
			if strings.Contains(lines[i], unusedFunc) {
				for j, secondLine := range lines[i:] {
					if strings.Contains(secondLine, "EndFunc") {				
						i = i + j + 1
						break
					}
				}

			}
		}
		modLines = append(modLines, lines[i])
	}

	return modLines
}


func main() {
	flag.Parse()

	if inputFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	lines, err := file2lines(inputFile)
	if err != nil {
		panic(err)
	}
	
	modLines := removeFuncs(removeVars(decryptStrings(lines)))

	fileContent := ""
	for _, line := range modLines {
		fileContent += line
		fileContent += "\n"
	}

	ioutil.WriteFile("new_file.au3", []byte(fileContent), 0644)
}