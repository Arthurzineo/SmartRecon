package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/url"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "time"
    "net/http" // Importado para resolver o erro undefined: http
)

var (
    target       string
    headers      map[string]string
    elasticURL   string
    authUser     string
    authPassword string
    dicSistemas  map[string][2]string
)

func init() {
    if len(os.Args) < 2 {
        fmt.Println("Uso: programa <target>")
        os.Exit(1)
    }

    target = os.Args[1]
    headers = map[string]string{
        "Accept":       "application/json",
        "Content-Type": "application/json",
    }
    elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_search", target)
    authUser = "admin"
    authPassword = "StrongAdmin123!" // Incluindo a senha diretamente no código

    dicSistemas = make(map[string][2]string)
}

func consulta() error {
    data := map[string]interface{}{
        "size": 10000,
    }
    jsonData, err := json.Marshal(data)
    if err != nil {
        return fmt.Errorf("Erro ao converter dados para JSON: %v", err)
    }

    req, err := http.NewRequest("GET", elasticURL, strings.NewReader(string(jsonData)))
    if err != nil {
        return fmt.Errorf("Erro ao criar requisição HTTP: %v", err)
    }

    for key, value := range headers {
        req.Header.Set(key, value)
    }
    req.SetBasicAuth(authUser, authPassword)

    // Ignora a verificação de certificado TLS (atenção: não recomendado para produção)
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{
        Transport: tr,
        Timeout:   30 * time.Second,
    }

    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("Erro ao executar requisição HTTP: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("Erro ao ler o corpo da resposta: %v", err)
    }

    // Analisa o JSON
    var parseScan map[string]interface{}
    err = json.Unmarshal(body, &parseScan)
    if err != nil {
        return fmt.Errorf("Erro ao analisar JSON: %v", err)
    }

    // Processa os hits
    hits, ok := parseScan["hits"].(map[string]interface{})
    if !ok {
        return fmt.Errorf("Erro ao analisar 'hits'")
    }
    hitsHits, ok := hits["hits"].([]interface{})
    if !ok {
        return fmt.Errorf("Erro ao analisar 'hits.hits'")
    }
    for _, hit := range hitsHits {
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
        if _, exists := dicSistemas[urlOriginal]; !exists {
            serverDomain, _ := source["server.domain"].(string)
            serverIP, _ := source["server.ip"].(string)
            dicSistemas[urlOriginal] = [2]string{serverDomain, serverIP}
        }
    }

    return nil
}

func extractDomain(rawURL string) string {
    // Remove protocolo se presente
    urlStr := rawURL
    if strings.HasPrefix(rawURL, "http://") {
        urlStr = strings.TrimPrefix(rawURL, "http://")
    } else if strings.HasPrefix(rawURL, "https://") {
        urlStr = strings.TrimPrefix(rawURL, "https://")
    }

    // Remove tudo após a primeira '/'
    idx := strings.Index(urlStr, "/")
    if idx != -1 {
        urlStr = urlStr[:idx]
    }

    return urlStr
}

func extractProtocolAndDomain(rawURL string) string {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        // Se ocorrer erro ao parsear, retorna a URL original
        return rawURL
    }
    protocol := parsedURL.Scheme
    domain := parsedURL.Host
    return fmt.Sprintf("%s://%s", protocol, domain)
}

func parseURL(rawURL string) (protocol string, port int64, err error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return "", 0, err
    }
    protocol = u.Scheme
    portStr := u.Port()
    if portStr == "" {
        // Porta não especificada, usar porta padrão
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

func parallel() error {
    // Remove o arquivo de log anterior
    logFilePath := filepath.Join("/docker/data", target, "temp", "gobuster_parallel.log")
    os.Remove(logFilePath)

    // Cria o diretório temp se não existir
    tempDir := filepath.Join("/docker/data", target, "temp")
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
    for sis, values := range dicSistemas {
        serverDomain := values[0]
        serverIP := values[1]

        // Ajusta o serverDomain para remover protocolo e caminho
        adjustedServerDomain := extractDomain(serverDomain)

        // Ajusta o sis para incluir protocolo e domínio, sem o caminho
        adjustedSis := extractProtocolAndDomain(sis)

        // Extrai protocolo e porta de adjustedSis
        protocol, port, err := parseURL(adjustedSis)
        if err != nil {
            fmt.Printf("Erro ao parsear URL %s: %v\n", adjustedSis, err)
            continue
        }

        // Gera o comando com os argumentos necessários
        cmdLine := fmt.Sprintf("/recon/program/scripts/gobuster_parse %s %s %s %s %s %d\n", target, adjustedServerDomain, serverIP, adjustedSis, protocol, port)
        _, err = file.WriteString(cmdLine)
        if err != nil {
            return fmt.Errorf("Erro ao escrever no arquivo de log: %v", err)
        }
    }

    fmt.Println("[+] PROCESSANDO GOBUSTER \n")

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
