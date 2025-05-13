package main

import (
	"log"
	"os"

	"github.com/gregdel/pushover"
)

func HandleOther() {
	summary := os.Getenv("SUMMARY")
	textFilename := os.Getenv("TEXT_FILENAME")
	text := "no description provided"
	if textFilename != "" {
		t, err := os.ReadFile(textFilename)
		if err != nil {
			text = "failed to read text file"
		} else {
			text = string(t)
		}
	}

	// send message via Pushover
	apiKey := os.Getenv("PUSHOVER_API_KEY")
	if apiKey == "" {
		log.Println("PUSHOVER_API_KEY environment variable is not set")
		os.Exit(1)
	}
	userKey := os.Getenv("PUSHOVER_USER_KEY")
	if userKey == "" {
		log.Println("PUSHOVER_USER_KEY environment variable is not set")
		os.Exit(1)
	}
	app := pushover.New(apiKey)
	recipient := pushover.NewRecipient(userKey)
	message := pushover.NewMessageWithTitle(text, summary)
	_, err := app.SendMessage(message, recipient)
	if err != nil {
		log.Println(summary)
		log.Println(text)
		log.Printf("Failed to send message: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
