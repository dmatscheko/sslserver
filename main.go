package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// Command represents a command that can be sent from the parent to the child
// or from the child to the parent.
type Command struct {
	// Type is the type of command (e.g. "get", "put", etc.).
	Type string
	// Name is the optional name of the file or certificate for the command.
	Name string
	// Data is the payload for the command.
	Data []byte
}

const (
	cmdGet       = "[get]"
	cmdPut       = "[put]"
	cmdDelete    = "[delete]"
	cmdTerminate = "[terminate]"
)

// Create the channels for communication between the parent and child.
var parentToChildCh = make(chan Command)
var childToParentCh = make(chan Command)

// If the current process is the child.
var isChild = false

func main() {
	// Check if the current process is the child.
	for _, arg := range os.Args[1:] {
		if arg == "-child" {
			isChild = true
			break
		}
	}

	// Initialize the output for the logger.
	initLogging()

	// Read config file.
	readConfig()

	if isChild {
		log.Println("This program is the child")
		initChild()
	} else {
		log.Println("This program is the parent")
		initParent()
	}
}

// This is the parent program that handles the certificate storage and logging.
func initParent() {
	cmd := exec.Command(os.Args[0], "-child")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Setting handler for commands from child")
	go func() {
		// Create a new bufio.Reader to read from standard output.
		reader := bufio.NewReader(stdout)

		for {
			// Read the first line of output, which is the command type.
			commandType, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			commandType = strings.TrimSpace(commandType)

			// If it is not a command, then it will be sent to the logger.
			if !(commandType == cmdGet || commandType == cmdPut || commandType == cmdDelete || commandType == cmdTerminate) {
				childToParentCh <- Command{
					Type: commandType,
					Name: "",
					Data: nil,
				}
				continue
			}

			// Read the second line of output, which is the optional file name for the command.
			fileName, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			fileName = strings.TrimSpace(fileName)

			// Read the next line of output, which is the number of bytes of data.
			dataLengthStr, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			dataLength, err := strconv.Atoi(strings.TrimSpace(dataLengthStr))
			if err != nil {
				log.Fatal(err)
			}

			// Read the data from the output.
			data := make([]byte, dataLength)
			_, err = io.ReadFull(reader, data)
			if err != nil {
				log.Fatal(err)
			}

			// Create a Command struct with the command type and data.
			command := Command{
				Type: commandType,
				Name: fileName,
				Data: data,
			}

			// log.Println("Command from child:", command)

			// Send the Command struct to the child-to-parent channel.
			childToParentCh <- command
		}
	}()

	log.Println("Setting handler for commands to child")
	go func() {
		w := bufio.NewWriter(stdin)
		for {
			// Receive a Command struct from the parent-to-child channel.
			command := <-parentToChildCh

			// log.Println("Command to child:", command)

			// Write the command type to the childs stdin.
			if _, err := w.WriteString(command.Type); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}

			// Write the file name for the command to the childs stdin.
			if _, err := w.WriteString(command.Name); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}

			// Write the number of bytes of data to the childs stdin.
			if _, err := w.WriteString(strconv.Itoa(len(command.Data))); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}
			w.Flush()

			// Write the data to the childs stdin.
			if _, err := stdin.Write(command.Data); err != nil {
				log.Fatal(err)
			}
		}
	}()

	log.Println("Running child")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	log.Println("Setting trap to exit when child exits")
	go func() {
		cmd.Wait()
		os.Exit(0)
	}()

	log.Println("Waiting for commands")
	cache := autocert.DirCache(config.CertificateCacheDirectory)
	ctx := context.Background()
	for command := range childToParentCh {
		// Handle the command from the child program.
		switch command.Type {
		case cmdGet:
			// Handle the "get" command
			cert, err := cache.Get(ctx, string(command.Name))
			if err != nil {
				cert = []byte{}
			}
			// Create a Command struct with the response type and data.
			response := Command{Type: cmdGet, Name: command.Name, Data: cert}
			parentToChildCh <- response
		case cmdPut:
			// Handle the "put" command.
			err := cache.Put(ctx, command.Name, command.Data)
			if err != nil {
				log.Println("Could not store certificate:", err)
			}
		case cmdDelete:
			// Handle the "delete" command.
			err := cache.Delete(ctx, command.Name)
			if err != nil {
				log.Println("Could not delete certificate:", err)
			}
		default:
			log.Println(command.Type)
		}
	}
}

// This is the child program that runs the server.
func initChild() {
	go func() {
		// Create a new bufio.Reader to read from standard input.
		reader := bufio.NewReader(os.Stdin)

		for {
			// Read the first line of output, which is the command type.
			commandType, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			commandType = strings.TrimSpace(commandType)

			// If it is not a command, then it will be ignored.
			if !(commandType == cmdGet || commandType == cmdPut || commandType == cmdDelete || commandType == cmdTerminate) {
				continue
			}

			// Read the second line of output, which is the optional file name for the command.
			fileName, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			fileName = strings.TrimSpace(fileName)

			// Read the next line of output, which is the number of bytes of data.
			dataLengthStr, err := reader.ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			dataLength, err := strconv.Atoi(strings.TrimSpace(dataLengthStr))
			if err != nil {
				log.Fatal(err)
			}

			// Read the data from the output.
			data := make([]byte, dataLength)
			_, err = io.ReadFull(reader, data)
			if err != nil {
				log.Fatal(err)
			}

			// Create a Command struct with the command type and data.
			command := Command{
				Type: commandType,
				Name: fileName,
				Data: data,
			}

			if command.Type == cmdTerminate {
				// The child does not have to send the command to the parent-to-child. It can handle it directly.
				terminateServer()
			} else {
				// Send the Command struct to the parent-to-child channel.
				parentToChildCh <- command
			}
		}
	}()

	go func() {
		w := bufio.NewWriter(os.Stdout)
		for {
			// Receive a Command struct from the child-to-parent channel.
			command := <-childToParentCh

			// Write the command type to the childs stdout.
			if _, err := w.WriteString(command.Type); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}

			// Write the file name for the command to the childs stdout.
			if _, err := w.WriteString(command.Name); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}

			// Write the number of bytes of data to the childs stdout.
			if _, err := w.WriteString(strconv.Itoa(len(command.Data))); err != nil {
				log.Fatal(err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}
			w.Flush()

			// Write the data to the childs stdout.
			if _, err := os.Stdout.Write(command.Data); err != nil {
				log.Fatal(err)
			}
		}
	}()

	// Initialize (fill) the white list and the cert cache.
	log.Println("Checking certificates...")
	initCertificates()

	// Set permissions for the files and directores in (and including) the web root.
	log.Println("Setting file permissions for web root")
	err := setPermissions(config.WebRootDirectory)
	if err != nil {
		log.Fatal("Could not set permissions:", err)
	}

	// Initialize (fill) the file cache.
	log.Println("Caching files...")
	err = fillCache(config.WebRootDirectory)
	if err != nil {
		log.Fatal(err)
	}

	runServer()

	os.Exit(0)
}

// TODO: if the parent receives ctrl+C, sigterm, etc, it should send a terminate command to the child (the server).
// TODO: if the child terminates, the parent should exit too, but with the error level of the child.
