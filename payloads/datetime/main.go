package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// Get the current date and time
	currentTime := time.Now()

	// Format the date and time to use as the file name
	// Example: 2024-02-17_15-04-05.txt
	fileName := currentTime.Format("2006-01-02_15-04-05") + ".txt"

	// Specify the path to the user's Downloads folder
	// This path works for Windows, adjust accordingly for macOS or Linux
	downloadsPath := filepath.Join("C:\\Users\\phill\\Downloads", fileName)

	// For macOS and Linux, you might want to use something like:
	// downloadsPath := filepath.Join(os.Getenv("HOME"), "Downloads", fileName)

	// Create the file in the Downloads folder
	file, err := os.Create(downloadsPath)
	if err != nil {
		fmt.Println("Error creating the file:", err)
		return
	}
	defer file.Close()

	// Write a simple message to the file
	message := "This file was created on " + currentTime.Format("2006-01-02 15:04:05")
	_, err = file.WriteString(message)
	if err != nil {
		fmt.Println("Error writing to the file:", err)
		return
	}

	fmt.Println("File saved successfully:", downloadsPath)
}
