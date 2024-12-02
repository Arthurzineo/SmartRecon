package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Estrutura para enviar ao Elasticsearch
type WebEnum struct {
	Timestamp                  time.Time `json:"@timestamp"`
	ServerAddress              string    `json:"server.address"`
	ServerDomain               string    `json:"server.domain"`
	ServerIP                   string    `json:"server.ip"`
	ServerPort                 int64     `json:"server.port"`
	NetworkProtocol            string    `json:"network.protocol"`
	URLPath                    string    `json:"url.path"`
	HTTPResponseStatusCode     int64     `json:"http.response.status_code"`
	URLOriginal                string    `json:"url.original"`
	URLFull                    string    `json:"url.full"`
	VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

// Variáveis globais
var (
	target        string
	subdomain     string
	ip            string
	headers       map[string]string
	url           string
	authUser      string
	authPassword  string
	scanner       string
	x             string
	containerName string
	saida         string
	result        string
)

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 4 {
		fmt.Println("Uso: programa <target> <subdomain> <ip>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	subdomain = os.Args[2]
	ip = os.Args[3]

	// Define as variáveis necessárias
	url = fmt.Sprintf("https://localhost:9200/%s-webenum/_doc?refresh", target)
	authUser = "admin"
	authPassword = "StrongAdmin123!"
	scanner = "httpx"

	// Gera um UUID e extrai a primeira parte
	xUUID := uuid.New().String()
	x = strings.Split(xUUID, "-")[0]

	// Monta o nome do contêiner e o nome do arquivo de saída
	containerName = fmt.Sprintf("%s-%s-httpx", target, x)
	saida = fmt.Sprintf("httpx-%s.xml", x)

	// Define os headers
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
}

func executa() {
	// Constrói os argumentos do comando
	args := []string{
		"run",
		"--rm",
		"--name",
		containerName,
		"kali-recon",
		"bash",
		"-c",
		fmt.Sprintf("echo '%s' | httpx -json --no-color", subdomain),
	}

	// Para depuração
	fmt.Println("Comando sendo executado:")
	fmt.Println("docker", strings.Join(args, " "))

	// Executa o comando e captura apenas o stdout
	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	if err != nil {
		// Captura a saída de erro separadamente
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Erro ao executar o comando: %v\n", exitError)
			fmt.Printf("Saída de erro do comando:\n%s\n", string(exitError.Stderr))
		} else {
			fmt.Printf("Erro ao executar o comando: %v\n", err)
		}
		result = ""
		return
	}

	// Armazena a saída
	result = string(output)
}

func parse() {
	if result != "" {
		linhas := strings.Split(strings.TrimSpace(result), "\n")
		for _, linha := range linhas {
			if linha == "" {
				continue
			}

			// Parseia cada linha JSON
			var httpxResult map[string]interface{}
			err := json.Unmarshal([]byte(linha), &httpxResult)
			if err != nil {
				fmt.Printf("Erro ao parsear JSON: %v\n", err)
				continue
			}

			// Extrai os campos necessários
			networkProtocol := ""
			if urlValue, ok := httpxResult["url"].(string); ok {
				if strings.HasPrefix(urlValue, "https://") {
					networkProtocol = "https"
				} else if strings.HasPrefix(urlValue, "http://") {
					networkProtocol = "http"
				}
			}

			serverPort := int64(0)
			if portValue, ok := httpxResult["port"].(float64); ok {
				serverPort = int64(portValue)
			}

			urlPath := "/"
			if pathValue, ok := httpxResult["path"].(string); ok {
				urlPath = pathValue
			}

			httpResponseStatusCode := int64(0)
			if statusCodeValue, ok := httpxResult["status_code"].(float64); ok {
				httpResponseStatusCode = int64(statusCodeValue)
			}

			urlOriginal := ""
			if _, ok := httpxResult["host"].(string); ok {
				urlOriginal = fmt.Sprintf("%s://%s", networkProtocol, subdomain)
			}

			urlFull := ""
			if urlValue, ok := httpxResult["url"].(string); ok {
				urlFull = urlValue
			}

			// Constrói a estrutura WebEnum
			data := WebEnum{
				Timestamp:                  time.Now(),
				ServerAddress:              subdomain,
				ServerDomain:               subdomain,
				ServerIP:                   ip,
				ServerPort:                 serverPort,
				NetworkProtocol:            networkProtocol,
				URLPath:                    urlPath,
				HTTPResponseStatusCode:     httpResponseStatusCode,
				URLOriginal:                urlOriginal,
				URLFull:                    urlFull,
				VulnerabilityScannerVendor: scanner,
			}

			// Envia os dados para o Elasticsearch
			sendToElastic(data)
		}
	}
}

func parseInt64(s string) int64 {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func sendToElastic(data WebEnum) {
	// Converte os dados para JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Erro ao converter dados para JSON: %v\n", err)
		return
	}

	// Cria a requisição HTTP
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
		return
	}

	// Define os headers e a autenticação
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPassword)

	// Ignora a verificação do certificado TLS
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Envia a requisição
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Lê a resposta
	bodyBytes, _ := io.ReadAll(resp.Body)

	// Imprime o código de status e o corpo da resposta
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Resposta do Elasticsearch: %s\n", string(bodyBytes))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		fmt.Printf("Falha ao enviar dados para Elasticsearch. Código de status: %d\n", resp.StatusCode)
	} else {
		fmt.Println("Dados enviados com sucesso para Elasticsearch.")
	}
}

func main() {
	executa()
	parse()
}
