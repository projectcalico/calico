package dict

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"time"
)

// RetrieveRandomName returns the a random name from the file at filePath.
// The file should contain one name per line.
func RetrieveRandomName(filePath string) (name string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var potentialNames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		potentialNames = append(potentialNames, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(potentialNames) == 0 {
		return "", fmt.Errorf("no candidate names found in %s", filePath)
	}
	randomIndex := rand.Intn(len(potentialNames))
	return potentialNames[randomIndex], nil
}

// GetCandidateName returns a candidate name in the format "YYYY-MM-DD-<random name>"
// where <random name> is a random name from the file at filePath.
func GetCandidateName(rootDir string) (string, error) {
	filePath := rootDir + "/fixham/assets/wordlist.txt"
	now := time.Now()
	date := now.Format("2006-01-02")
	randomName, err := RetrieveRandomName(filePath)
	if err != nil {
		return "", err
	}
	return date + "-" + randomName, nil
}
