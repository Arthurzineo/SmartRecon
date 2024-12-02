package main

import (
    "bufio"
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

// Estrutura para enviar vulnerabilidades web ao Elasticsearch
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

// Estrutura para enviar vulnerabilidades de infraestrutura ao Elasticsearch
type InfraVuln struct {
    Timestamp                  time.Time `json:"@timestamp"`
    ServerAddress              string    `json:"server.address"`
    ServerIP                   string    `json:"server.ip"`
    ServerPort                 int64     `json:"server.port"`
    NetworkProtocol            string    `json:"network.protocol"`
    ServiceName                string    `json:"service.name"`
    VulnerabilityDescription   string    `json:"vulnerability.description"`
    VulnerabilityName          string    `json:"vulnerability.name"`
    VulnerabilitySeverity      string    `json:"vulnerability.severity"`
    VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

// Estrutura para representar a saída JSON do Nuclei
type NucleiOutput struct {
    MatchedAt   string `json:"matched-at"`
    Info        Info   `json:"info"`
    MatcherName string `json:"matcher-name"`
    Host        string `json:"host"`
    IP          string `json:"ip,omitempty"`
    // Adicione outros campos conforme necessário
}

type Info struct {
    Name        string `json:"name"`
    Severity    string `json:"severity"`
    Description string `json:"description"`
    Reference   string `json:"reference,omitempty"`
}

// Variáveis globais
var (
    target          string
    sistema         string
    elasticURLWeb   string
    elasticURLInfra string
    authUser        string
    authPassword    string
    scanner         string
    x               string
    containerName   string
    saida           string
    hora            string
    headers         map[string]string
)

// Cliente HTTP global com timeout
var httpClient = &http.Client{
    Timeout: 10 * time.Second, // Define o timeout desejado
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Atenção: Não recomendado para produção
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

    // Define as URLs do Elasticsearch para webvuln e infravuln
    elasticURLWeb = fmt.Sprintf("https://localhost:9200/%s-webvuln/_doc?refresh", target)
    elasticURLInfra = fmt.Sprintf("https://localhost:9200/%s-infravuln/_doc?refresh", target)

    // Define as credenciais de autenticação
    authUser = "admin"
    authPassword = "StrongAdmin123!"

    scanner = "nuclei"
    hora = time.Now().Format(time.RFC3339)

    // Gera um UUID e extrai a primeira parte
    xUUID := uuid.New().String()
    x = strings.Split(xUUID, "-")[0]

    // Monta o nome do contêiner e o nome do arquivo de saída
    containerName = fmt.Sprintf("%s-%s-nuclei", target, x)
    saida = fmt.Sprintf("nuclei-%s.json", x)

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

    // Monta os argumentos do comando
    args := []string{
        "run",
        "--rm",
        "--name",
        containerName,
        "-v",
        volume, // Usa o caminho do volume dinâmico
        image,  // Use a imagem personalizada que inclui o nuclei
        "nuclei",
        "-u",
        sistema,
        "-bs", "1000",
        "-t",
        "/root/nuclei-templates/",
        "-o",
        "/data/" + saida,
        "-j",
    }

    // Para depuração
    fmt.Println("Comando sendo executado:")
    fmt.Println("docker", strings.Join(args, " "))

    // Executa o comando sem capturar a saída, pois ela é direcionada para um arquivo
    cmd := exec.Command("docker", args...)

    // Capturando a saída (stdout e stderr combinados)
    var output bytes.Buffer
    cmd.Stdout = &output
    cmd.Stderr = &output

    err := cmd.Run()
    if err != nil {
        fmt.Printf("Erro ao executar o comando: %v\n", err)
        fmt.Printf("Saída do comando: %s\n", output.String())
        return err
    }

    fmt.Printf("Saída do comando: %s\n", output.String())
    fmt.Println("Contêiner Docker executado com sucesso.")
    return nil
}

func parse() {
    err := executa(sistema)
    if err != nil {
        fmt.Println("Erro ao executar o Nuclei.")
        return
    }

    jsonPath := fmt.Sprintf("/recon/data/%s/temp/%s", target, saida)

    // Verifica se o arquivo existe
    if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
        fmt.Printf("Arquivo de saída não encontrado: %s\n", jsonPath)
        return
    }

    // Abre o arquivo JSON
    file, err := os.Open(jsonPath)
    if err != nil {
        fmt.Printf("Erro ao abrir o arquivo JSON: %v\n", err)
        return
    }
    defer file.Close()

    // Cria um scanner para ler o arquivo linha por linha
    scannerFile := bufio.NewScanner(file)

    fmt.Println("Arquivo JSON analisado com sucesso.")

    for scannerFile.Scan() {
        line := scannerFile.Text()
        if strings.TrimSpace(line) == "" {
            continue
        }

        var nucleiOutput NucleiOutput
        err := json.Unmarshal([]byte(line), &nucleiOutput)
        if err != nil {
            fmt.Printf("Erro ao analisar a linha JSON: %v\n", err)
            continue
        }

        // Verifica se 'matched-at' contém 'http' ou 'https'
        if strings.Contains(nucleiOutput.MatchedAt, "http") || strings.Contains(nucleiOutput.MatchedAt, "https") {
            // Dados para o índice 'webvuln'
            webVuln := WebVuln{
                Timestamp:                  time.Now(),
                ServerAddress:              nucleiOutput.Host,
                ServerDomain:               nucleiOutput.Host,
                ServerIP:                   getIP(nucleiOutput.IP),
                ServerPort:                 getPort(nucleiOutput.MatchedAt),
                NetworkProtocol:            getProtocol(nucleiOutput.MatchedAt),
                ServiceName:                "N/A",
                URLPath:                    getURLPath(nucleiOutput.MatchedAt),
                HTTPResponseStatusCode:     200, // Como no código original, está fixo
                VulnerabilityDescription:   getDescription(nucleiOutput),
                VulnerabilityName:          getName(nucleiOutput),
                VulnerabilitySeverity:      nucleiOutput.Info.Severity,
                URLOriginal:                nucleiOutput.Host,
                URLFull:                    nucleiOutput.MatchedAt,
                VulnerabilityScannerVendor: scanner,
            }

            fmt.Printf("Linha correspondida: %s, Status Code: %d\n", webVuln.URLPath, webVuln.HTTPResponseStatusCode)

            // Envia os dados para o Elasticsearch
            sendToElasticWeb(webVuln)
        } else {
            // Dados para o índice 'infravuln'
            infraVuln := InfraVuln{
                Timestamp:                  time.Now(),
                ServerAddress:              nucleiOutput.Host,
                ServerIP:                   getIP(nucleiOutput.IP),
                ServerPort:                 getPort(nucleiOutput.MatchedAt),
                NetworkProtocol:            getInfraProtocol(nucleiOutput.MatchedAt),
                ServiceName:                "N/A",
                VulnerabilityDescription:   getDescription(nucleiOutput),
                VulnerabilityName:          getName(nucleiOutput),
                VulnerabilitySeverity:      nucleiOutput.Info.Severity,
                VulnerabilityScannerVendor: scanner,
            }

            fmt.Printf("Vulnerabilidade de Infraestrutura: %s, Severity: %s\n", infraVuln.VulnerabilityName, infraVuln.VulnerabilitySeverity)

            // Envia os dados para o Elasticsearch
            sendToElasticInfra(infraVuln)
        }
    }

    if err := scannerFile.Err(); err != nil {
        fmt.Printf("Erro ao ler o arquivo JSON: %v\n", err)
    }
}

// Função para obter o IP, retornando '0.0.0.0' se vazio
func getIP(ip string) string {
    if strings.TrimSpace(ip) == "" {
        return "0.0.0.0"
    }
    return ip
}

// Função para extrair o protocolo a partir da URL
func getProtocol(url string) string {
    parts := strings.Split(url, ":")
    if len(parts) > 0 {
        return strings.ToLower(parts[0])
    }
    return "N/A"
}

// Função para extrair o caminho da URL
func getURLPath(url string) string {
    parts := strings.SplitN(url, "/", 4)
    if len(parts) >= 4 {
        return "/" + parts[3]
    }
    return "/"
}

// Função para obter a descrição da vulnerabilidade
func getDescription(nucleiOutput NucleiOutput) string {
    desc := strings.ReplaceAll(nucleiOutput.Info.Description, "\n ", "")
    desc = strings.ReplaceAll(desc, " \n", "")
    if desc == "" {
        return nucleiOutput.Info.Name
    }
    // Adiciona 'matcher-name' se disponível
    if nucleiOutput.MatcherName != "" {
        desc += " " + nucleiOutput.MatcherName
    }
    return desc
}

// Função para obter o nome da vulnerabilidade
func getName(nucleiOutput NucleiOutput) string {
    return nucleiOutput.Info.Name
}

// Função para obter a porta a partir da URL
func getPort(matchedAt string) int64 {
    // Exemplo de 'matchedAt': "http://businesscorp.com.br:80/path"
    parts := strings.SplitN(matchedAt, "://", 2)
    if len(parts) < 2 {
        return 0
    }
    hostPortPath := parts[1]
    // Separar host e porta
    hostPort := strings.SplitN(hostPortPath, "/", 2)[0]
    hostPortParts := strings.Split(hostPort, ":")
    if len(hostPortParts) == 2 {
        portStr := hostPortParts[1]
        port, err := strconv.ParseInt(portStr, 10, 64)
        if err == nil {
            return port
        }
    }
    // Retorna 0 se não conseguir extrair
    return 0
}

// Função para obter o protocolo de infraestrutura baseado na porta
func getInfraProtocol(matchedAt string) string {
    port := getPort(matchedAt)
    switch port {
    case 21:
        return "ftp"
    case 22:
        return "ssh"
    case 23:
        return "telnet"
    case 3389:
        return "rdp"
    default:
        return "N/A"
    }
}

// Função para converter string para int64, retornando 0 em caso de erro
func parseInt64(s string) int64 {
    i, err := strconv.ParseInt(s, 10, 64)
    if err != nil {
        return 0
    }
    return i
}

// Função sendToElasticWeb para enviar WebVuln ao Elasticsearch
func sendToElasticWeb(data WebVuln) {
    // Converte os dados para JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        fmt.Printf("Erro ao converter dados para JSON (webvuln): %v\n", err)
        return
    }

    // Cria a requisição HTTP
    req, err := http.NewRequest("POST", elasticURLWeb, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Erro ao criar requisição HTTP (webvuln): %v\n", err)
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
        fmt.Printf("Erro ao enviar dados para Elasticsearch (webvuln): %v\n", err)
        return
    }
    defer resp.Body.Close()

    // Lê a resposta
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Erro ao ler a resposta do Elasticsearch (webvuln): %v\n", err)
        return
    }
    fmt.Printf("Resposta do Elasticsearch (webvuln): %s\n", string(bodyBytes))
}

// Função sendToElasticInfra para enviar InfraVuln ao Elasticsearch
func sendToElasticInfra(data InfraVuln) {
    // Converte os dados para JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        fmt.Printf("Erro ao converter dados para JSON (infravuln): %v\n", err)
        return
    }

    // Cria a requisição HTTP
    req, err := http.NewRequest("POST", elasticURLInfra, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Erro ao criar requisição HTTP (infravuln): %v\n", err)
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
        fmt.Printf("Erro ao enviar dados para Elasticsearch (infravuln): %v\n", err)
        return
    }
    defer resp.Body.Close()

    // Lê a resposta
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Erro ao ler a resposta do Elasticsearch (infravuln): %v\n", err)
        return
    }
    fmt.Printf("Resposta do Elasticsearch (infravuln): %s\n", string(bodyBytes))
}

func main() {
    parse()
}
