package main

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	path := "goip/"
	mappings, err := readPropertiesFile(path + "IPAddressResources.properties")
	if err != nil {
		log.Fatal(err)
	}
	source := writeSourceFile(mappings)
	_ = os.WriteFile(path+"ipaddressresources.go", source, 0644)
}

func readPropertiesFile(filename string) (map[string]string, error) {
	config := make(map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			firstChar := line[0]
			if firstChar != '#' && firstChar != '=' {
				if divIndex := strings.Index(line, "="); divIndex > 0 && divIndex < len(line)-1 {
					key := line[:divIndex]
					value := line[divIndex+1:]
					config[key] = value
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

func writeSourceFile(mappings map[string]string) []byte {
	i := 0
	valLen := 0
	indexMappings := make(map[string]int)
	indices := make([]int, len(mappings))
	valsArray := make([]string, len(mappings))
	// create the mappings from string to index into slice, from slice entry to string index
	for key, val := range mappings {
		indexMappings[key] = i
		indices[i] = valLen
		valsArray[i] = val
		valLen += len(val)
		i++
	}

	// now prepare the source code for each of the three elements,
	// the map, the slice, and the string
	mappingsStr := "\n"
	for key, val := range indexMappings {
		mappingsStr += "`" + key + "`: " + strconv.Itoa(val) + ",\n"
	}

	indicesStr := ""
	for i, val := range indices {
		if i%10 == 0 {
			indicesStr += "\n"
		}
		indicesStr += strconv.Itoa(val) + ","
	}

	strStr := "\n"
	for i, val := range valsArray {
		if i > 0 {
			strStr += "+\n"
		}
		strStr += "`" + val + "`"
	}

	bytes :=
		`//
// Copyright 2023 Evgenii Pochechuev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by running convert.go from the go workspace directory (the one containing the src folder). Do not edit.

package ipaddr

var keyStrMap = map[string]int {` + mappingsStr + `
}

var strIndices = []int{` + indicesStr + `
}

var strVals =` + strStr + `

func lookupStr(key string) (result string) {
	if index, ok := keyStrMap[key]; ok {
		start, end := strIndices[index], strIndices[index+1]
		result = strVals[start:end]
	}
	return
}
`
	return []byte(bytes)
}
