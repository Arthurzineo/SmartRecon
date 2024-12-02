package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	target       string
	headers      map[string]string
	elasticURL   string
	authUser     string
	authPassword string
	listSistemas []string
)

func init() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: programa <target>")
		os.Exit(1)
	}

	// Recebe o argumento da linha de comando
	target = os.Args[1]

	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_search", target)

	authUser = "admin"
	authPassword = "StrongAdmin123!" // Insira sua senha aqui

	listSistemas = []string{}
}

func consulta() error {
	data := map[string]interface{}{
		"size": 10000,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("Erro ao converter dados para JSON: %v", err)
	}

	req, err := http.NewRequest("POST", elasticURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Erro ao criar requisição HTTP: %v", err)
	}

	// Define os headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Define a autenticação básica
	req.SetBasicAuth(authUser, authPassword)

	// Ignora a verificação do certificado TLS
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Envia a requisição
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Erro ao fazer requisição HTTP: %v", err)
	}
	defer resp.Body.Close()

	// Lê a resposta
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Erro ao ler resposta HTTP: %v", err)
	}

	// Analisa o JSON
	var parseScan map[string]interface{}
	err = json.Unmarshal(bodyBytes, &parseScan)
	if err != nil {
		return fmt.Errorf("Erro ao analisar JSON: %v", err)
	}

	// Extrai os hits
	hitsData, ok := parseScan["hits"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Formato inválido: 'hits' não encontrado")
	}

	hits, ok := hitsData["hits"].([]interface{})
	if !ok {
		return fmt.Errorf("Formato inválido: 'hits.hits' não encontrado")
	}

	// Utiliza um mapa para evitar duplicatas
	listSistemasSet := make(map[string]struct{})

	for _, hit := range hits {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}
		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}
		urlOriginal, ok := source["url.original"].(string)
		if !ok {
			continue
		}

		if _, exists := listSistemasSet[urlOriginal]; !exists {
			listSistemas = append(listSistemas, urlOriginal)
			listSistemasSet[urlOriginal] = struct{}{}
		}
	}

	return nil
}

func parallel() error {
	// Define o caminho do arquivo de log
	logFilePath := filepath.Join("/recon/data", target, "temp", "nikto_parallel.log")

	// Remove o arquivo de log anterior, se existir
	os.Remove(logFilePath)

	// Cria o diretório temp se não existir
	tempDir := filepath.Join("/recon/data", target, "temp")
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		return fmt.Errorf("Erro ao criar o diretório temp: %v", err)
	}

	// Abre o arquivo de log para escrita
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Erro ao abrir o arquivo de log: %v", err)
	}
	defer file.Close()

	// Escreve os comandos no arquivo de log
	for _, sis := range listSistemas {
		line := fmt.Sprintf("/recon/program/scripts/nikto_parse %s %s\n", target, sis)
		_, err := file.WriteString(line)
		if err != nil {
			return fmt.Errorf("Erro ao escrever no arquivo de log: %v", err)
		}
	}

	fmt.Println("[+] PROCESSANDO NIKTO \n")

	// Executa os comandos usando o GNU Parallel
	cmdStr := fmt.Sprintf("cat %s | parallel -u", logFilePath)
	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Erro ao executar comandos em paralelo: %v", err)
	}

	return nil
}

func main() {
	err := consulta()
	if err != nil {
		fmt.Printf("Erro na consulta: %v\n", err)
		os.Exit(1)
	}

	err = parallel()
	if err != nil {
		fmt.Printf("Erro na função parallel: %v\n", err)
		os.Exit(1)
	}
}
