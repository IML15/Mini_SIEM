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

	"gopkg.in/yaml.v3"
)

// Estructura de configuración
type Config struct {
	ServerURL      string `yaml:"server_url"`
	Hostname       string `yaml:"hostname"`
	LogFile        string `yaml:"log_file"`
	PollIntervalMs int    `yaml:"poll_interval_ms"`
}

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
	cfg          Config
	sshFailRegex = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
)

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &cfg)
}

func sendEvent(event SecurityEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cfg.ServerURL, "application/json", bytes.NewBuffer(data))
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
			Hostname:   cfg.Hostname,
			SourceType: "linux_auth",
			RawMessage: line,
			Network:    &NetworkDetails{SrcIP: ip},
			Auth:       &AuthDetails{User: user, Success: false},
		}
	}
	return nil
}

func main() {
	configFile := "config.yaml"
	if err := loadConfig(configFile); err != nil {
		log.Fatalf("[-] Error cargando configuración (%s): %v", configFile, err)
	}

	fmt.Printf("[*] Iniciando Mini-SIEM Agent en host '%s'\n", cfg.Hostname)
	fmt.Printf("[*] Monitoreando archivo: %s -> Envíos a: %s\n", cfg.LogFile, cfg.ServerURL)

	// Crear el archivo si no existe
	file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		log.Fatalf("[-] Error abriendo archivo de log: %v", err)
	}
	defer file.Close()

	// Ir al final del archivo para procesar únicamente líneas nuevas
	file.Seek(0, io.SeekEnd)

	buffer := make([]byte, 1024)
	var leftover string
	pollDelay := time.Duration(cfg.PollIntervalMs) * time.Millisecond

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
					fmt.Printf("[+] Evento detectado -> IP: %s, User: %s\n", event.Network.SrcIP, event.Auth.User)
					if err := sendEvent(*event); err != nil {
						fmt.Printf("[-] Error enviando evento al SIEM: %v\n", err)
					}
				}
			}
		}

		if err != nil && err != io.EOF {
			log.Printf("[-] Error leyendo stream: %v", err)
		}

		time.Sleep(pollDelay)
	}
}