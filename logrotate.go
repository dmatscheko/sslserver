package main

import (
	"io"
	"log"
	"os"
	"time"
)

func initLogging() {
	// Return if no log file should be written.
	if config.LogFile == "" {
		return
	}

	// Open the log file for appending.
	f, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// Do not close the file, because the logger should always be able to write into it!
	// defer f.Close()

	// Create a writer that writes to the log file and to stdout.
	w := io.MultiWriter(f, os.Stdout)

	// Modify the output of the default logger.
	log.SetOutput(w)

	// Log rotation only works, when the server is not in a jail.
	if !config.JailProcess {
		// Rotate the log files every day.
		go func() {
			for range time.Tick(24 * time.Hour) {
				// Remove the oldest log file.
				os.Remove(config.LogFile + ".3")

				// Closing the current log file is not necessary,
				// because os.Rename() closes the file automatically.
				// f.Close()

				// Rename the log files.
				os.Rename(config.LogFile+".2", config.LogFile+".3")
				os.Rename(config.LogFile+".1", config.LogFile+".2")
				os.Rename(config.LogFile, config.LogFile+".1")

				// Create a new log file.
				f, err := os.Create(config.LogFile)
				if err != nil {
					log.Fatal(err)
				}

				// Create a writer that writes to the log file and to stdout.
				w = io.MultiWriter(f, os.Stdout)

				// Modify the output of the default logger.
				log.SetOutput(w)
			}
		}()
	}
}
