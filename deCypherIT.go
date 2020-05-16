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
	shellcodeFunc    string
	shellcodeVar     string
)

func init() {
	flag.StringVar(&inputFile, "input_file", "", "input file with the  obfsucated nanocore file")
	flag.StringVar(&shellcodeFunc, "shellcode_func", "", "function that constructs the shellcode")
	flag.StringVar(&shellcodeVar, "var_name", "", "first variable name for the shellcode creation")
}

func trimStringFromEquals(s string) string {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx+1]
	}
	return s
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

func decryptStrings(lines []string) []string {
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
				tempLine = trimStringFromEquals(tempLine)
				tempLine += " "
				tempLine += decodedStr + "; DECRYPTED LINE"

				fmt.Printf("[+] complete line %d: %s\n", i, tempLine)
			} else {
				tempLine = trimStringFromEquals(tempLine)
				tempLine += " "
				dst := make([]byte, hex.EncodedLen(len(decodedStr)))
				hex.Encode(dst, []byte(decodedStr))
				res := fmt.Sprintf("\"%s\"; POTENTIAL SHELLCODE", dst)
				tempLine += res
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

func removeVars(lines []string) []string {
	getVarName := regexp.MustCompile(`(?m)(Dim|Local|Global Const|Global|Local Const)\s\$(?P<Name>.+?)\s`)

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

		// count the number of occurences
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

func removeFuncs(iterations int, lines []string) []string {
	var getFuncName = regexp.MustCompile(`(?m)Func\s(?P<Name>.+)\(`)

	for pass := 0; pass < iterations; pass++ {
		unusedFuncs := []string{}
		modLines := []string{}

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
				if strings.Contains(lines[i], unusedFunc) && strings.Contains(lines[i], "Func") {
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
		lines = modLines
	}

	return lines
}

func getFuncFromScript(fname string, lines []string) []string {
	funcStr := fmt.Sprintf("Func %s(", fname)
	funcStartLine := 0

	for i, line := range lines {
		if strings.Contains(line, funcStr) {
			funcStartLine = i
			break
		}
	}

	funcEndLine := 0

	for i, line := range lines[funcStartLine:] {
		if strings.Contains(line, "EndFunc") {
			funcEndLine = i + funcStartLine
			break
		}
	}

	return lines[funcStartLine : funcEndLine+1]
}

func listVarsFromFunction(funcLines []string) []string {
	getVarName := regexp.MustCompile(`(?m)(Dim|Local|Global Const|Global|Local Const)\s\$(?P<Name>.+?)\s`)
	modLines := []string{}
	varsInUse := []string{}

	for i, line := range funcLines {
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
		varsInUse = append(varsInUse, result["Name"])
	}

	return varsInUse
}

func find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func getShellcodeFromShellcodeFunc(funcLines []string, varName string) ([]byte, error) {
	var getShellcode = regexp.MustCompile(`(?m)Local\s\$(?P<equals>[a-zA-Z0-9\$]+)\s=\s(?P<name>[a-zA-Z0-9\$]+)\s&\s"(?P<content>[a-zA-Z0-9\$]+)"`)
	res := []byte{}
	processedLines := []string{}
	for i, line := range funcLines {

		match := getShellcode.FindStringSubmatch(line)

		if len(match) == 0 {
			continue
		}

		result := make(map[string]string)

		// turn the regex groups into a map
		for k, name := range getShellcode.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[k]
			}
		}

		if !strings.Contains(line, varName) || find(processedLines, line) {
			continue
		}

		fmt.Println(result["content"])
		processedLines = append(processedLines, line)
		decodedContent, err := hex.DecodeString(result["content"])
		if err != nil {
			return nil, err
		}

		varName = result["equals"]

		res = append(res, decodedContent...)
	}

	return res, nil
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

	modLines := removeVars(removeFuncs(50, decryptStrings(lines)))

	fileContent := ""
	for _, line := range modLines {
		fileContent += line
		fileContent += "\n"
	}

	if shellcodeFunc != "" {
		cont := getFuncFromScript(shellcodeFunc, modLines)
		shellcode, err := getShellcodeFromShellcodeFunc(cont, shellcodeVar)
		if err != nil {
			fmt.Println("unavle to extract shellcode")
			os.Exit(1)
		}

		fmt.Printf("[+] Extracted %d bytes of shellcode from %s\n", len(shellcode), shellcodeFunc)

		os.Exit(1)
	}

	ioutil.WriteFile("new_file.au3", []byte(fileContent), 0644)
}
