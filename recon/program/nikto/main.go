package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
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
type WebVuln struct {
	Timestamp                  time.Time `json:"@timestamp"`
	ServerAddress              string    `json:"server.address"`
	ServerDomain               string    `json:"server.domain"`
	ServerIP                   string    `json:"server.ip"`
	ServerPort                 int64     `json:"server.port"`
	NetworkProtocol            string    `json:"network.protocol"`
	ServiceName                string    `json:"service.name"`
	URLPath                    string    `json:"url.path"`
	HTTPResponseStatusCode     int64     `json:"http.response.status_code"`
	VulnerabilityDescription   string    `json:"vulnerability.description"`
	VulnerabilityName          string    `json:"vulnerability.name"`
	VulnerabilitySeverity      string    `json:"vulnerability.severity"`
	URLOriginal                string    `json:"url.original"`
	URLFull                    string    `json:"url.full"`
	VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

// Estrutura para representar o elemento raiz <niktoscans>
type NiktoScans struct {
	XMLName    xml.Name    `xml:"niktoscans"`
	NiktoScans []NiktoScan `xml:"niktoscan"`
}

// Estrutura para representar o elemento <niktoscan>
type NiktoScan struct {
	XMLName     xml.Name    `xml:"niktoscan"`
	ScanDetails ScanDetails `xml:"scandetails"`
}

// Estrutura para representar o elemento <scandetails>
type ScanDetails struct {
	XMLName         xml.Name `xml:"scandetails"`
	TargetIP        string   `xml:"targetip,attr"`
	TargetHostname  string   `xml:"targethostname,attr"`
	TargetPort      string   `xml:"targetport,attr"`
	Sitename        string   `xml:"sitename,attr"`
	NetworkProtocol string   // Será extraído do Sitename
	ServiceName     string   // Será extraído do Sitename
	Items           []Item   `xml:"item"`
}

// Estrutura para representar o elemento <item>
type Item struct {
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
	References  string `xml:"references"`
}

// Variáveis globais
var (
	target        string
	sistema       string
	elasticURL    string
	authUser      string
	authPassword  string
	scanner       string
	x             string
	containerName string
	saida         string
	hora          string
	headers       map[string]string
)

// Cliente HTTP global com timeout
var httpClient = &http.Client{
	Timeout: 10 * time.Second, // Define o timeout desejado
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 3 {
		fmt.Println("Uso: programa <target> <sistema>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	sistema = os.Args[2]

	// Define as variáveis necessárias
	elasticURL = fmt.Sprintf("https://localhost:9200/%s-webvuln/_doc?refresh", target)
	authUser = "admin"
	authPassword = "StrongAdmin123!"
	scanner = "nikto"
	hora = time.Now().Format(time.RFC3339)

	// Gera um UUID e extrai a primeira parte
	xUUID := uuid.New().String()
	x = strings.Split(xUUID, "-")[0]

	// Monta o nome do contêiner e o nome do arquivo de saída
	containerName = fmt.Sprintf("%s-%s-nikto", target, x)
	saida = fmt.Sprintf("nikto-%s.xml", x)

	// Define os headers
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
}

func executa(sistema string) error {
	// Construir o caminho do volume usando a variável global 'target'
	volume := fmt.Sprintf("/recon/data/%s/temp:/data", target)

	// Escolha a imagem correta: use 'kali-recon'
	image := "kali-recon"

	// Monta os argumentos do comando Docker
	args := []string{
		"run",
		"--rm",
		"--name",
		containerName,
		"-v",
		volume, // Usa o caminho do volume dinâmico
		image,  // Use a imagem personalizada que inclui o nikto
		"nikto",
		"-host",
		sistema,
		"-output",
		"/data/" + saida,
	}

	// Para depuração: imprime o comando que será executado
	fmt.Println("Comando sendo executado:")
	fmt.Println("docker", strings.Join(args, " "))

	// Executa o comando Docker
	cmd := exec.Command("docker", args...)

	// Capturando a saída (stdout e stderr combinados)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		fmt.Printf("Saída do comando: %s\n", output.String())
		return nil
	}

	// Opcional: imprimir a saída do comando para depuração
	fmt.Printf("Saída do comando: %s\n", output.String())

	fmt.Println("Contêiner Docker executado com sucesso.")
	return nil
}

func parse() {
	 executa(sistema)


	// Caminho completo do arquivo XML de saída
	xmlPath := fmt.Sprintf("/recon/data/%s/temp/%s", target, saida)

	// Verifica se o arquivo existe
	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		fmt.Printf("Arquivo de saída não encontrado: %s\n", xmlPath)
		return
	}

	// Abre o arquivo XML
	file, err := os.Open(xmlPath)
	if err != nil {
		fmt.Printf("Erro ao abrir o arquivo XML: %v\n", err)
		return
	}
	defer file.Close()

	// Analisa o XML
	var report NiktoScans
	decoder := xml.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		fmt.Printf("Erro ao analisar o XML: %v\n", err)
		return
	}

	fmt.Println("Arquivo XML analisado com sucesso.")

	// Itera sobre cada niktoscan
	for _, niktoScan := range report.NiktoScans {
		scandetail := niktoScan.ScanDetails

		// Extrai protocolo e nome do serviço a partir de 'sitename'
		protocol := "N/A"
		serviceName := "N/A"
		if strings.Contains(scandetail.Sitename, "://") {
			parts := strings.Split(scandetail.Sitename, "://")
			if len(parts) > 1 {
				protocol = strings.ToLower(parts[0])
				serviceName = strings.ToLower(parts[0])
			}
		}

		// Itera sobre cada item
		for _, item := range scandetail.Items {
			// Limpa os campos retirando quebras de linha e espaços
			description := strings.ReplaceAll(strings.ReplaceAll(item.Description, "\n ", ""), " \n", "")
			uri := strings.ReplaceAll(strings.ReplaceAll(item.URI, "\n ", ""), " \n", "")
			namelink := strings.ReplaceAll(strings.ReplaceAll(item.NameLink, "\n ", ""), " \n", "")

			// Constrói a estrutura WebVuln
			port, err := strconv.ParseInt(scandetail.TargetPort, 10, 64)
			if err != nil {
				fmt.Printf("Erro ao converter server.port: %v\n", err)
				port = 0
			}

			data := WebVuln{
				Timestamp:                  time.Now(),
				ServerAddress:              scandetail.TargetHostname,
				ServerDomain:               scandetail.TargetHostname,
				ServerIP:                   scandetail.TargetIP,
				ServerPort:                 port,
				NetworkProtocol:            protocol,
				ServiceName:                serviceName,
				URLPath:                    uri,
				HTTPResponseStatusCode:     200, // Como no código original, está fixo
				VulnerabilityDescription:   description,
				VulnerabilityName:          description,
				VulnerabilitySeverity:      "N/A",
				URLOriginal:                sistema,
				URLFull:                    namelink,
				VulnerabilityScannerVendor: scanner,
			}

			fmt.Printf("Vulnerabilidade encontrada: %s, Caminho: %s\n", data.VulnerabilityName, data.URLPath)

			// Envia os dados para o Elasticsearch
			sendToElastic(data)
		}
	}
}

func sendToElastic(data WebVuln) {
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

	// Define os headers e a autenticação usando o mapa 'headers' definido globalmente
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.SetBasicAuth(authUser, authPassword)

	// Envia a requisição
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Lê a resposta
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Erro ao ler a resposta do Elasticsearch: %v\n", err)
		return
	}
	fmt.Printf("Resposta do Elasticsearch: %s\n", string(bodyBytes))
}

func main() {
	parse()
}
