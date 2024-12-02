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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
)

// Tipos e estruturas
type Subdomain struct {
	Timestamp                  string `json:"@timestamp"`
	ServerAddress              string `json:"server.address"`
	ServerDomain               string `json:"server.domain"`
	ServerNameserver           string `json:"server.nameserver"`
	ServerIP                   string `json:"server.ip"`
	ServerIPBlock              string `json:"server.ipblock"`
	VulnerabilityScannerVendor string `json:"vulnerability.scanner.vendor"`
}

type RDAPResponse struct {
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
}

type IPInfo struct {
	Query string `json:"query"`
	CIDR  string `json:"as"` // Representa o bloco (organização e ASN)
}

// Estrutura para decodificar a saída JSON do subfinder (não mais necessária para sublist3r)
type Dados struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// Variáveis globais
var (
	target        string
	domain        string
	headers       map[string]string
	url           string
	authUser      string
	authPassword  string
	hora          string
	scannerType   string
	dicSubdomain  map[string]interface{}
	x             string
	containerName string
	saida         string
)

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 3 {
		fmt.Println("Uso: programa <target> <domain>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	domain = os.Args[2]

	// Define os headers
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	// Monta a URL
	url = "https://localhost:9200/" + target + "-subdomain/_doc?refresh"

	// Autenticação
	authUser = "admin"
	authPassword = "StrongAdmin123!"

	// Obtém a hora atual no formato especificado
	hora = time.Now().Format("2006-01-02T15:04:05Z07:00")

	// Scanner
	scannerType = "sublist3r"

	// Dicionário vazio (mapa em Go)
	dicSubdomain = make(map[string]interface{})

	// Gera um UUID versão 1 e obtém a primeira parte
	xUUID, err := uuid.NewV1()
	if err != nil {
		fmt.Printf("Falha ao gerar UUID1: %v\n", err)
		os.Exit(1)
	}
	xParts := strings.Split(xUUID.String(), "-")
	x = xParts[0]

	// Monta o nome do contêiner
	containerName = target + "-" + x + "-sublist3r"

	// Monta o nome do arquivo de saída
	saida = "sublist3r-" + x + ".txt"
}

func main() {
	executa()
	parse()
}

func executa() {
	// Utiliza filepath.Join para construir o caminho
	hostPath := filepath.Join("/recon", "data", target, "temp")

	// Construção do comando Docker com caminhos corretos
	// Utilizamos -o para gerar saída em texto
	command := fmt.Sprintf(
		"docker run --rm --name %s -v %s:/data kali-recon sublist3r -d %s -o /data/%s",
		containerName, hostPath, domain, saida,
	)

	// Exibindo o comando para depuração (opcional)
	fmt.Println("Comando sendo executado:")
	fmt.Println(command)

	// Configurando o comando para execução no shell
	cmd := exec.Command("bash", "-c", command)

	// Capturando a saída (stdout e stderr combinados)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		fmt.Printf("Saída do comando:\n%s", string(output))
		os.Exit(1)
	}

	// Mostrando a saída do comando
	fmt.Printf("Saída do comando:\n%s", string(output))
}

func parse() {
	// Utiliza filepath.Join para construir o caminho do arquivo
	caminhoArquivo := filepath.Join("/recon", "data", target, "temp", saida)

	// Verificar se o arquivo existe antes de tentar abrir
	if _, err := os.Stat(caminhoArquivo); os.IsNotExist(err) {
		log.Fatalf("Arquivo %s não existe. Verifique se o comando Docker foi executado corretamente.", caminhoArquivo)
	}

	file, err := os.Open(caminhoArquivo)
	if err != nil {
		log.Fatalf("Erro ao abrir o arquivo: %v", err)
	}
	defer file.Close()

	subdomains := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue // Pula linhas vazias
		}
		// Adiciona ao mapa (ignora duplicatas automaticamente)
		subdomains[linha] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler o arquivo: %v", err)
	}

	// Variáveis para controle de concorrência
	var wg sync.WaitGroup
	concurrencyLimit := 10 // Número máximo de goroutines simultâneas
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	for subdomain := range subdomains {
		wg.Add(1)
		semaphoreChan <- struct{}{} // Bloqueia se atingir o limite de goroutines

		// Processa cada subdomínio em uma goroutine
		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-semaphoreChan }() // Libera o espaço no semáforo

			ip := getHostIP(subdomain)
			ipBlock := getIPBlock(ip)

			subd := Subdomain{
				Timestamp:                  hora,
				ServerAddress:              subdomain,
				ServerDomain:               subdomain,
				ServerNameserver:           rdapDomain(subdomain),
				ServerIP:                   ip,
				ServerIPBlock:              ipBlock,
				VulnerabilityScannerVendor: scannerType,
			}
			fmt.Printf("Subdomain Object: %+v\n", subd)

			// Converte o objeto em JSON
			jsonData, err := json.Marshal(subd)
			if err != nil {
				fmt.Printf("Erro ao serializar subdomain %s: %v\n", subdomain, err)
				return
			}

			// Envia para o Elasticsearch
			sendToElastic(url, jsonData)

		}(subdomain)
	}

	wg.Wait() // Aguarda todas as goroutines terminarem
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

func rdapDomain(domain string) string {
	url := "https://rdap.registro.br/domain/" + domain
	response, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return ""
	}

	var rdapResponse RDAPResponse
	err = json.Unmarshal(body, &rdapResponse)
	if err != nil {
		return ""
	}

	var nameservers []string
	for _, ns := range rdapResponse.Nameservers {
		nameservers = append(nameservers, ns.LdhName)
	}

	return strings.Join(nameservers, ",")
}

func sendToElastic(url string, data []byte) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPassword)

	// Ignora a verificação do certificado TLS (se necessário)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("Falha ao enviar dados para Elasticsearch. Status: %s, Body: %s\n", resp.Status, string(bodyBytes))
	} else {
		fmt.Printf("Dados enviados com sucesso para Elasticsearch.\n")
	}
}
