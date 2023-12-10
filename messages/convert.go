package main

import (
	"bufio"
	"os"
	"strings"
)

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
