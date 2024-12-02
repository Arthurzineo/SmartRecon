package main

import (
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/clbanning/mxj"
	"github.com/gofrs/uuid"
)

// Estrutura para enviar ao Elasticsearch
type PortScan struct {
	Timestamp                  time.Time `json:"@timestamp"`
	ServerAddress              string    `json:"server.address"`
	NetworkProtocol            string    `json:"network.protocol"`
	ServerIP                   string    `json:"server.ip"`
	ServerPort                 int64     `json:"server.port"`
	ServerIPBlock              string    `json:"server.ipblock"`
	ServiceName                string    `json:"service.name"`
	ServiceState               string    `json:"service.state"`
	ApplicationVersionNumber   string    `json:"application.version.number"`
	NetworkTransport           string    `json:"network.transport"`
	NetworkType                string    `json:"network.type"`
	VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

var (
	target        string
	headers       map[string]string
	url           string
	authUser      string
	authPassword  string
	scannerType   string
	x             string
	containerName string
	saida         string
	ipx           string
)

// Mutex para proteger o acesso ao slice portScans
var mutex sync.Mutex

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 3 {
		fmt.Println("Uso: programa <target> <ip>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	ipx = os.Args[2]

	// Define os headers (não utilizados no código atual, pode ser removido)
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	// Monta a URL do Elasticsearch
	url = "https://localhost:9200/" + target + "-portscan/_doc?refresh"

	// Autenticação do Elasticsearch
	authUser = "admin"
	authPassword = "StrongAdmin123!"

	// Tipo de Scanner
	scannerType = "Nmap"

	// Gera um UUID versão 1 e obtém a primeira parte
	xUUID, err := uuid.NewV1()
	if err != nil {
		fmt.Printf("Falha ao gerar UUID1: %v\n", err)
		os.Exit(1)
	}
	xParts := strings.Split(xUUID.String(), "-")
	x = xParts[0]

	// Monta o nome do contêiner
	containerName = fmt.Sprintf("%s-%s-nmap", target, x)

	// Monta o nome do arquivo de saída
	saida = fmt.Sprintf("nmap-%s.xml", x)
}

func executa() {
	// Define hostPath de forma consistente com o sistema operacional
	var hostPath string
	if isWindows() {
		hostPath = fmt.Sprintf("C:/recon/data/%s/temp", target)
	} else {
		hostPath = filepath.Join("/recon", "data", target, "temp")
	}

	// Cria o diretório se não existir
	err := os.MkdirAll(hostPath, os.ModePerm)
	if err != nil {
		fmt.Printf("Erro ao criar o diretório: %v\n", err)
		os.Exit(1)
	}

	// Define a imagem Docker personalizada (assegure-se de ter criado conforme as instruções)
	dockerImage := "kali-recon"

	// Construção do comando Docker sem redirecionamento de saída no host
	command := fmt.Sprintf(
		"docker run --rm --name %s -v %s:/data %s nmap -sSV -Pn %s -oX /data/%s",
		containerName, hostPath, dockerImage, ipx, saida,
	)

	// Exibindo o comando para depuração (opcional)
	fmt.Println("Comando sendo executado:")
	fmt.Println(command)

	// Configurando o comando para execução no shell
	var cmd *exec.Cmd
	if isWindows() {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("bash", "-c", command)
	}

	// Capturando a saída (stdout e stderr combinados)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		fmt.Printf("Saída do comando:\n%s\n", string(output))
		os.Exit(1)
	}

	// Como a saída está redirecionada para o arquivo, 'output' deve estar vazio
	// Portanto, nenhuma ação é necessária aqui
}

func parse() {
	// Define hostPath de forma consistente com o sistema operacional
	var hostPath string
	if isWindows() {
		hostPath = fmt.Sprintf("C:/recon/data/%s/temp", target)
	} else {
		hostPath = filepath.Join("/recon", "data", target, "temp")
	}

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

	mv, err := mxj.NewMapXmlReader(file)
	if err != nil {
		log.Fatalf("Erro ao fazer o parsing do XML: %v", err)
	}

	// Extrai o tempo de início do scan
	startTimeStr, err := mv.ValueForPath("nmaprun.-start")
	if err != nil {
		log.Fatalf("Erro ao extrair o tempo de início: %v", err)
	}
	startTimeInt, err := strconv.ParseInt(fmt.Sprintf("%v", startTimeStr), 10, 64)
	if err != nil {
		log.Fatalf("Erro ao converter o tempo de início: %v", err)
	}
	timestamp := time.Unix(startTimeInt, 0)

	// Extrai o IP do servidor e o tipo de rede
	addressData, err := mv.ValueForPath("nmaprun.host.address")
	if err != nil {
		log.Fatalf("Erro ao extrair o endereço: %v", err)
	}

	var serverIP, networkType string

	if addressMap, ok := addressData.(map[string]interface{}); ok {
		serverIP = fmt.Sprintf("%v", addressMap["-addr"])
		networkType = fmt.Sprintf("%v", addressMap["-addrtype"])
	} else {
		log.Println("Estrutura de endereço inválida")
	}

	// Calcula o bloco de IP
	serverIPBlock := getIPBlock(serverIP)

	// Extrai o hostname (endereço do servidor)
	var serverAddress string

	if hostnames, err := mv.ValueForPath("nmaprun.host.hostnames.hostname"); err == nil {
		switch h := hostnames.(type) {
		case []interface{}:
			for _, hEntry := range h {
				if hMap, ok := hEntry.(map[string]interface{}); ok {
					if hMap["-type"] == "user" {
						if name, exists := hMap["-name"]; exists {
							serverAddress = fmt.Sprintf("%v", name)
							break // Encontrou o hostname do tipo "user"
						}
					}
				}
			}
		case map[string]interface{}:
			// Caso haja apenas um hostname
			hMap := h
			if hMap["-type"] == "user" {
				if name, exists := hMap["-name"]; exists {
					serverAddress = fmt.Sprintf("%v", name)
				}
			}
		default:
			log.Println("Tipo inesperado para hostnames")
		}
	} else {
		log.Println("Hostname não encontrado")
	}

	// Extrai as informações das portas
	portsData, err := mv.ValueForPath("nmaprun.host.ports")
	if err != nil {
		log.Fatalf("Erro ao extrair portas: %v", err)
	}

	// Slice para armazenar todos os PortScans
	var portScans []PortScan

	// WaitGroup para esperar o processamento das portas
	var wg sync.WaitGroup

	// Itera sobre as portas e cria estruturas PortScan
	if portsMap, ok := portsData.(map[string]interface{}); ok {
		if portEntries, exists := portsMap["port"]; exists {
			switch portData := portEntries.(type) {
			case []interface{}:
				for _, portEntry := range portData {
					if portMap, ok := portEntry.(map[string]interface{}); ok {
						wg.Add(1)
						// Processa cada porta em uma goroutine
						go func(portMap map[string]interface{}) {
							defer wg.Done()
							portScan := parsePortScan(portMap, serverIP, serverAddress, networkType, serverIPBlock, timestamp)
							// Protege o acesso ao slice
							mutex.Lock()
							portScans = append(portScans, portScan)
							mutex.Unlock()
						}(portMap)
					}
				}
			case map[string]interface{}:
				// Apenas uma porta
				wg.Add(1)
				go func(portMap map[string]interface{}) {
					defer wg.Done()
					portScan := parsePortScan(portMap, serverIP, serverAddress, networkType, serverIPBlock, timestamp)
					// Protege o acesso ao slice
					mutex.Lock()
					portScans = append(portScans, portScan)
					mutex.Unlock()
				}(portData)
			default:
				log.Println("Tipo inesperado para portas")
			}
		} else {
			log.Println("Nenhuma porta encontrada")
		}
	} else {
		log.Println("Estrutura de portas inválida")
	}

	// Aguarda o processamento das portas
	wg.Wait()

	// Envia todos os PortScans para o Elasticsearch
	for _, portScan := range portScans {
		// Converte portScan para JSON
		jsonData, err := json.Marshal(portScan)
		if err != nil {
			log.Printf("Erro ao converter para JSON: %v", err)
			continue
		}
		// Envia para o Elasticsearch
		sendToElastic(url, jsonData)
	}
}

func parsePortScan(portMap map[string]interface{}, serverIP, serverAddress, networkType, serverIPBlock string, timestamp time.Time) PortScan {
	portIDStr := fmt.Sprintf("%v", portMap["-portid"])
	portID, err := strconv.ParseInt(portIDStr, 10, 64)
	if err != nil {
		portID = 0
	}

	networkProtocol := fmt.Sprintf("%v", portMap["-protocol"])

	var serviceName, applicationVersionNumber, serviceState, networkTransport string

	// Obtém o estado
	if stateData, ok := portMap["state"].(map[string]interface{}); ok {
		if state, exists := stateData["-state"]; exists {
			serviceState = fmt.Sprintf("%v", state)
		}
	}

	// Obtém o serviço
	if serviceData, ok := portMap["service"].(map[string]interface{}); ok {
		if name, exists := serviceData["-name"]; exists {
			serviceName = fmt.Sprintf("%v", name)
		}
		if version, exists := serviceData["-version"]; exists {
			applicationVersionNumber = fmt.Sprintf("%v", version)
		}
	}

	// Define o transporte de rede (por exemplo, "tcp" ou "udp")
	networkTransport = networkProtocol

	portScan := PortScan{
		Timestamp:                  timestamp,
		ServerAddress:              serverAddress,
		NetworkProtocol:            networkProtocol,
		ServerIP:                   serverIP,
		ServerPort:                 portID,
		ServerIPBlock:              serverIPBlock,
		ServiceName:                serviceName,
		ServiceState:               serviceState,
		ApplicationVersionNumber:   applicationVersionNumber,
		NetworkTransport:           networkTransport,
		NetworkType:                networkType,
		VulnerabilityScannerVendor: scannerType,
	}

	return portScan
}

func getIPBlock(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Desconhecido"
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		// IPv4 - Retorna o bloco /24
		return fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	}
	// IPv6 ou IP inválido
	return "Desconhecido"
}

func sendToElastic(url string, data []byte) {
	// Ignora a verificação do certificado TLS (se necessário)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPassword)

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

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

func main() {
	executa()
	parse()
}
