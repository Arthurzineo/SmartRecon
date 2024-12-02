package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "regexp"
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
    sistema       string
    headers       map[string]string
    elasticURL    string
    authUser      string
    authPassword  string
    scanner       string
    x             string
    containerName string
    hora          string

    // Cliente HTTP global com timeout
    httpClient = &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
)

func init() {
    // Verifica se os argumentos necessários foram fornecidos
    if len(os.Args) < 5 {
        fmt.Println("Uso: programa <target> <subdomain> <ip> <sistema>")
        os.Exit(1)
    }

    // Recebe os argumentos da linha de comando
    target = os.Args[1]
    subdomain = os.Args[2]
    ip = os.Args[3]
    sistema = os.Args[4]

    // Define as variáveis necessárias
    elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_doc?refresh", target)
    authUser = "admin"
    authPassword = "StrongAdmin123!"
    scanner = "gobuster"
    hora = time.Now().Format(time.RFC3339)

    // Gera um UUID e extrai a primeira parte
    xUUID := uuid.New().String()
    x = strings.Split(xUUID, "-")[0]

    // Monta o nome do contêiner
    containerName = fmt.Sprintf("%s-%s-gobuster", target, x)

    // Define os headers (não utilizados no código atual, pode ser removido)
    headers = map[string]string{
        "Accept":       "application/json",
        "Content-Type": "application/json",
    }
}

// Função para remover todas as sequências de escape ANSI
func removeAllANSIEscapeSequences(input string) string {
    // Regex para corresponder a todas as sequências de escape ANSI
    ansi := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
    return ansi.ReplaceAllString(input, "")
}

func executa() (string, error) {
    // Definir o caminho do volume
    volume := "/recon/lists:/scripts"

    // Manter a imagem do usuário
    image := "kali-recon"

    // Caminho do wordlist dentro do contêiner
    wordlist := "/scripts/common.txt"

    // Monta os argumentos do comando Docker
    args := []string{
        "run",
        "--rm",
        "--name",
        containerName,
        "-v",
        volume,
        image,
        "gobuster",
        "dir",
        "-u",
        sistema,
        "-w",
        wordlist,
        "--no-progress",
        "--follow-redirect",
        "--no-color",
        "-q",
    }

    // Para depuração
    fmt.Println("Comando sendo executado:")
    fmt.Println("docker", strings.Join(args, " "))

    // Executa o comando e captura a saída
    cmd := exec.Command("docker", args...)

    var stdout bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    fmt.Println("Executando o contêiner Docker...")

    err := cmd.Run()
    if err != nil {
        fmt.Printf("Erro ao executar o comando: %v\n", err)
        fmt.Printf("Saída do comando (stderr):\n%s\n", stderr.String())
        return "", err
    }

    fmt.Println("Contêiner Docker executado com sucesso.")
    return stdout.String(), nil
}

func parse() {
    output, err := executa()
    if err != nil {
        fmt.Println("Falha na execução do `gobuster`.")
        return
    }

    if strings.TrimSpace(output) == "" {
        fmt.Println("Nenhum resultado obtido do gobuster.")
        return
    }

    fmt.Println("Saída do gobuster:")
    fmt.Println(output)

    // Regex para analisar cada linha da saída
    lineRegex := regexp.MustCompile(`^(.+?)\s+\(Status:\s*(\d+)\)`)

    // Antes de processar os resultados, precisamos obter o protocolo e a porta do sistema
    protocol, port, err := parseSistemaURL(sistema)
    if err != nil {
        fmt.Printf("Erro ao parsear URL do sistema %s: %v\n", sistema, err)
        return
    }

    lines := strings.Split(output, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        // Remove sequências de escape ANSI
        line = removeAllANSIEscapeSequences(line)

        // Match da linha usando a regex
        matches := lineRegex.FindStringSubmatch(line)
        if matches == nil {
            fmt.Printf("Linha não corresponde ao padrão esperado: %s\n", line)
            continue
        }

        urlPath := matches[1]
        statusCodeStr := matches[2]
        statusCodeInt, err := strconv.ParseInt(statusCodeStr, 10, 64)
        if err != nil {
            fmt.Printf("Erro ao converter status code: %v\n", err)
            continue
        }

        fmt.Printf("Linha correspondida: %s, Status Code: %d\n", urlPath, statusCodeInt)

        // Constrói a estrutura WebEnum
        data := WebEnum{
            Timestamp:                  time.Now(),
            ServerAddress:              subdomain,
            ServerDomain:               subdomain,
            ServerIP:                   ip,
            ServerPort:                 port,
            NetworkProtocol:            protocol,
            URLPath:                    urlPath,
            HTTPResponseStatusCode:     statusCodeInt,
            URLOriginal:                sistema,
            URLFull:                    strings.TrimRight(sistema, "/") + urlPath,
            VulnerabilityScannerVendor: scanner,
        }

        // Envia os dados para o Elasticsearch
        sendToElastic(data)
    }
}

func parseSistemaURL(sistemaURL string) (protocol string, port int64, err error) {
    u, err := url.Parse(sistemaURL)
    if err != nil {
        return "", 0, err
    }
    protocol = u.Scheme
    portStr := u.Port()
    if portStr == "" {
        // Sem porta especificada, usa a porta padrão com base no protocolo
        if protocol == "http" {
            port = 80
        } else if protocol == "https" {
            port = 443
        } else {
            port = 0 // Protocolo desconhecido
        }
    } else {
        port, err = strconv.ParseInt(portStr, 10, 64)
        if err != nil {
            return "", 0, err
        }
    }
    return protocol, port, nil
}

func sendToElastic(data WebEnum) {
    // Converte os dados para JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        fmt.Printf("Erro ao converter dados para JSON: %v\n", err)
        return
    }

    fmt.Printf("Dados a serem enviados para Elasticsearch: %s\n", string(jsonData))

    // Cria um contexto com timeout de 10 segundos
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Cria a requisição HTTP com o contexto
    req, err := http.NewRequestWithContext(ctx, "POST", elasticURL, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
        return
    }

    // Define os headers e a autenticação
    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(authUser, authPassword)

    fmt.Println("Enviando dados para Elasticsearch...")

    // Envia a requisição utilizando o cliente HTTP global
    resp, err := httpClient.Do(req)
    if err != nil {
        fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
        return
    }
    defer resp.Body.Close()

    // Verifica o código de status da resposta
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        bodyBytes, _ := io.ReadAll(resp.Body)
        fmt.Printf("Falha ao enviar dados para Elasticsearch. Status: %s, Body: %s\n", resp.Status, string(bodyBytes))
        return
    }

    fmt.Println("Dados enviados para Elasticsearch com sucesso.")

    // Lê a resposta
    bodyBytes, _ := io.ReadAll(resp.Body)
    fmt.Printf("Resposta do Elasticsearch: %s\n", string(bodyBytes))
}

func main() {
    parse()
}
