package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

// Estructuras que coinciden con el esquema Pydantic del servidor
type NetworkDetails struct {
	SrcIP string `json:"src_ip,omitempty"`
}

type AuthDetails struct {
	User    string `json:"user,omitempty"`
	Success bool   `json:"success"`
}

type SecurityEvent struct {
	Hostname   string          `json:"hostname"`
	SourceType string          `json:"source_type"`
	RawMessage string          `json:"raw_message"`
	Network    *NetworkDetails `json:"network,omitempty"`
	Auth       *AuthDetails    `json:"auth,omitempty"`
}

var (
	serverURL = "http://localhost:8000/api/v1/events"
	hostname  = "srv-ubuntu-prod"
	logFile   = "test_auth.log"
	// Regex típica de fallo SSH: "Failed password for [invalid user] <user> from <ip>"
	sshFailRegex = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
)

func sendEvent(event SecurityEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("código inesperado: %d", resp.StatusCode)
	}
	return nil
}

func parseLine(line string) *SecurityEvent {
	matches := sshFailRegex.FindStringSubmatch(line)
	if len(matches) == 3 {
		user := matches[1]
		ip := matches[2]

		return &SecurityEvent{
			Hostname:   hostname,
			SourceType: "linux_auth",
			RawMessage: line,
			Network:    &NetworkDetails{SrcIP: ip},
			Auth:       &AuthDetails{User: user, Success: false},
		}
	}
	return nil
}

func main() {
	fmt.Printf("[*] Iniciando Mini-SIEM Agent monitoreando: %s\n", logFile)

	// Crear el archivo si no existe
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		log.Fatalf("Error abriendo archivo: %v", err)
	}
	defer file.Close()

	// Ir al final del archivo para leer solo líneas nuevas
	file.Seek(0, io.SeekEnd)

	buffer := make([]byte, 1024)
	var leftover string

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			leftover += string(buffer[:n])
			for {
				newlineIdx := -1
				for i, b := range leftover {
					if b == '\n' {
						newlineIdx = i
						break
					}
				}
				if newlineIdx == -1 {
					break
				}

				line := leftover[:newlineIdx]
				leftover = leftover[newlineIdx+1:]

				if len(line) == 0 {
					continue
				}

				if event := parseLine(line); event != nil {
					fmt.Printf("[+] Intento SSH fallido detectado -> IP: %s, User: %s\n", event.Network.SrcIP, event.Auth.User)
					if err := sendEvent(*event); err != nil {
						fmt.Printf("[-] Error enviando evento: %v\n", err)
					}
				}
			}
		}

		if err != nil && err != io.EOF {
			log.Printf("Error leyendo: %v", err)
		}

		time.Sleep(500 * time.Millisecond)
	}
}