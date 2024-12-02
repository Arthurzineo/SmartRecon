package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Estrutura para enviar ao Elasticsearch
type WebEnum struct {
	Timestamp                  time.Time `json:"@timestamp"`
	ServerAddress              string    `json:"server.address"`
	ServerDomain               string    `json:"server.domain"`
	ServerIP                   string    `json:"server.ip"`
	ServerIPBlock              string    `json:"server.ipblock"`
	ServerPort                 int64     `json:"server.port"`
	NetworkProtocol            string    `json:"network.protocol"`
	URLPath                    string    `json:"url.path"`
	HTTPResponseStatusCode     int64     `json:"http.response.status_code"`
	URLOriginal                string    `json:"url.original"`
	URLFull                    string    `json:"url.full"`
	VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

// Estrutura para decodificar a resposta da API de IP
type IPInfo struct {
	Query string `json:"query"`
	CIDR  string `json:"as"` // Representa o bloco (organização e ASN)
}

// Variáveis globais
var (
	target        string
	subdomain     string
	ip            string
	headers       map[string]string
	elasticURL    string
	authUser      string
	authPassword  string
	scanner       string
	x             string
	containerName string
	saida         string
	result        []string
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
	elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_doc?refresh", target)
	authUser = "admin"
	authPassword = "StrongAdmin123!"
	scanner = "waybackurls"

	// Gera um UUID e extrai a primeira parte
	xUUID := uuid.New().String()
	x = strings.Split(xUUID, "-")[0]

	// Monta o nome do contêiner e o nome do arquivo de saída
	containerName = fmt.Sprintf("%s-%s-wayback", target, x)
	saida = fmt.Sprintf("wayback-%s.txt", x)

	// Define os headers (se necessário)
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
}

func executa() {
	// Define hostPath
	hostPath := filepath.Join("/recon", "data", target, "temp")

	// Cria o diretório se não existir
	err := os.MkdirAll(hostPath, os.ModePerm)
	if err != nil {
		fmt.Printf("Erro ao criar o diretório: %v\n", err)
		os.Exit(1)
	}

	// Construção do comando Docker com redirecionamento correto
	command := fmt.Sprintf(
		"docker run --rm --name %s -v %s:/data kali-recon bash -c 'echo %s | waybackurls' > %s/%s",
		containerName, hostPath, subdomain, hostPath, saida,
	)

	// Exibindo o comando para depuração (opcional)
	fmt.Println("Comando sendo executado:")
	fmt.Println(command)

	// Configurando o comando para execução no shell
	cmd := exec.Command("bash", "-c", command)

	// Executa o comando
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		return
	}
}

func parse() {
	// Define hostPath e caminhoArquivo
	hostPath := filepath.Join("/recon", "data", target, "temp")
	caminhoArquivo := filepath.Join(hostPath, saida)

	// Verificar se o arquivo existe antes de tentar abrir
	if _, err := os.Stat(caminhoArquivo); os.IsNotExist(err) {
		log.Fatalf("Arquivo %s não existe. Verifique se o comando Docker foi executado corretamente.", caminhoArquivo)
	}

	file, err := os.Open(caminhoArquivo)
	if err != nil {
		log.Fatalf("Erro ao abrir o arquivo: %v", err)
	}
	defer file.Close()

	urlsSet := make(map[string]struct{})

	scannerFile := bufio.NewScanner(file)
	for scannerFile.Scan() {
		linha := strings.TrimSpace(scannerFile.Text())
		if linha == "" {
			continue // Pula linhas vazias
		}
		// Adiciona ao mapa (ignora duplicatas automaticamente)
		urlsSet[linha] = struct{}{}
	}

	if err := scannerFile.Err(); err != nil {
		log.Fatalf("Erro ao ler o arquivo: %v", err)
	}

	// Variáveis para controle de concorrência
	var wg sync.WaitGroup
	concurrencyLimit := 10 // Número máximo de goroutines simultâneas
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	for urlStr := range urlsSet {
		wg.Add(1)
		semaphoreChan <- struct{}{} // Bloqueia se atingir o limite de goroutines

		// Processa cada URL em uma goroutine
		go func(urlStr string) {
			defer wg.Done()
			defer func() { <-semaphoreChan }() // Libera o espaço no semáforo

			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				fmt.Printf("Erro ao parsear URL %s: %v\n", urlStr, err)
				return
			}

			// Extrai o host
			host := parsedURL.Hostname()
			if host == "" {
				fmt.Printf("Host vazio na URL %s\n", urlStr)
				return
			}

			// Verifica se o host é um endereço IP
			if net.ParseIP(host) != nil {
				// Host é um endereço IP
				fmt.Printf("Ignorando URL com host de endereço IP: %s\n", urlStr)
				return
			}

			// Obtém o IP e o bloco de IP
			ip := getHostIP(host)
			ipBlock := getIPBlock(ip)

			// Tenta obter a porta
			var serverPort int64
			if parsedURL.Port() != "" {
				portNum, err := strconv.ParseInt(parsedURL.Port(), 10, 64)
				if err != nil {
					serverPort = 0
				} else {
					serverPort = portNum
				}
			} else {
				// Define a porta padrão com base no esquema
				if parsedURL.Scheme == "http" {
					serverPort = 80
				} else if parsedURL.Scheme == "https" {
					serverPort = 443
				} else {
					serverPort = 0
				}
			}

			// Constrói a estrutura WebEnum
			data := WebEnum{
				Timestamp:                  time.Now(),
				ServerAddress:              host,
				ServerDomain:               host,
				ServerIP:                   ip,
				ServerIPBlock:              ipBlock,
				ServerPort:                 serverPort,
				NetworkProtocol:            parsedURL.Scheme,
				URLPath:                    parsedURL.Path,
				HTTPResponseStatusCode:     200, // Pode ser ajustado conforme necessário
				URLOriginal:                fmt.Sprintf("%s://%s", parsedURL.Scheme, host),
				URLFull:                    urlStr,
				VulnerabilityScannerVendor: scanner,
			}

			// Envia os dados para o Elasticsearch
			sendToElastic(data)
		}(urlStr)
	}

	wg.Wait() // Aguarda todas as goroutines terminarem
}

func sendToElastic(data WebEnum) {
	// Converte os dados para JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Erro ao converter dados para JSON: %v\n", err)
		return
	}

	// Cria a requisição HTTP
	req, err := http.NewRequest("POST", elasticURL, bytes.NewBuffer(jsonData))
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

func getHostIP(hostname string) string {
	hostname = strings.TrimSpace(hostname)

	// Realiza a consulta DNS
	ips, err := net.LookupIP(hostname)
	if err != nil {
		fmt.Printf("Erro ao buscar IP para %s: %v\n", hostname, err)
		return "0.0.0.0"
	}

	// Retorna o primeiro IP válido
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return "0.0.0.0" // Nenhum IP encontrado
}

func getIPBlock(ip string) string {
	if ip == "0.0.0.0" {
		return "Desconhecido"
	}

	apiURL := fmt.Sprintf("http://ip-api.com/json/%s", ip)

	// Faz a requisição HTTP
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("Erro ao buscar bloco de IP para %s: %v\n", ip, err)
		return "Desconhecido"
	}
	defer resp.Body.Close()

	// Decodifica a resposta JSON
	var ipInfo IPInfo
	err = json.NewDecoder(resp.Body).Decode(&ipInfo)
	if err != nil {
		fmt.Printf("Erro ao decodificar resposta para %s: %v\n", ip, err)
		return "Desconhecido"
	}

	// Retorna o bloco ASN (ou similar) associado
	if ipInfo.CIDR != "" {
		return ipInfo.CIDR
	}

	return "Desconhecido"
}

func main() {
	executa()
	parse()
}
