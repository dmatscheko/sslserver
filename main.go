package main

// TODO: push new certificates through the clinet-server communication and enable the jail again

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// Command types.
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

	// Read config file.
	readConfig()

	// Initialize the output for the logger.
	initLogging()

	if isChild {
		log.Println("This program is the child")
		initChild()
	} else {
		// Print the config.
		printConfig(config)

		log.Println("This program is the parent")
		initParent()
	}

	os.Exit(0)
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
			select {
			// Receive a Command struct from the parent-to-child channel.
			case command, ok := <-parentToChildCh:
				if !ok {
					log.Fatal("parentToChildCh closed")
				}

				// log.Println("Command to child:", command)

				// Write the command type to the childs stdin.
				if _, err := w.WriteString(command.Type + "\n"); err != nil {
					log.Fatal(err)
				}

				// Write the file name for the command to the childs stdin.
				if _, err := w.WriteString(command.Name + "\n"); err != nil {
					log.Fatal(err)
				}

				// Write the number of bytes of data to the childs stdin.
				if _, err := w.WriteString(strconv.Itoa(len(command.Data)) + "\n"); err != nil {
					log.Fatal(err)
				}

				// Flush the writer to ensure the command is sent.
				if err := w.Flush(); err != nil {
					log.Fatal(err)
				}

				// Write the data to the childs stdin.
				if _, err := stdin.Write(command.Data); err != nil {
					log.Fatal(err)
				}

			case <-time.After(10 * time.Second):
				log.Println("Timeout waiting for command to child")
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
		// Closing the child-to-parent-channel, so that the command loop terminates and so the program.
		close(childToParentCh)
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
			log.SetPrefix("")
			log.SetFlags(0)
			log.Println(command.Type)
			log.SetPrefix("P ")
			log.SetFlags(log.LstdFlags)
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
			select {
			// Receive a Command struct from the child-to-parent channel.
			case command, ok := <-childToParentCh:
				if !ok {
					log.Fatal("childToParentCh closed")
				}

				// Write the command type to the childs stdout.
				if _, err := w.WriteString(command.Type + "\n"); err != nil {
					log.Fatal(err)
				}

				// Write the file name for the command to the childs stdout.
				if _, err := w.WriteString(command.Name + "\n"); err != nil {
					log.Fatal(err)
				}

				// Write the number of bytes of data to the childs stdout.
				if _, err := w.WriteString(strconv.Itoa(len(command.Data)) + "\n"); err != nil {
					log.Fatal(err)
				}
				// Flush the writer to ensure the command is sent.
				if err := w.Flush(); err != nil {
					log.Fatal(err)
				}

				// Write the data to the childs stdout.
				if _, err := os.Stdout.Write(command.Data); err != nil {
					log.Fatal(err)
				}

			case <-time.After(10 * time.Second):
				log.Println("Timeout waiting for command to parent")
			}
		}
	}()

	// Create a new autocert manager.
	manager := &autocert.Manager{
		Cache:       DirCache(""),
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  autocert.HostWhitelist(config.letsEncryptDomains...),
		RenewBefore: config.CertificateExpiryRefreshThreshold + 24*time.Hour, // This way, RenewBefore is always longer than the certificate expiry timeout when the server terminates.
		Email:       "admin-le@14.gy",                                        // TODO
		// Use staging server
		// Client: &acme.Client{
		// 	DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		// },
	}

	// Initialize (fill) the white list and the cert cache.
	// log.Println("Checking certificates...")
	// initCertificates(m)

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

	runServer(manager)
}
