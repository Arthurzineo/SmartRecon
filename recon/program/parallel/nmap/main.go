
package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

func main() {
    // Verifica se o argumento 'target' foi fornecido
    if len(os.Args) < 2 {
        fmt.Println("Uso: programa <target>")
        os.Exit(1)
    }

    target := os.Args[1]
    headers := map[string]string{
        "Accept":       "application/json",
        "Content-Type": "application/json",
    }
    url := fmt.Sprintf("https://localhost:9200/%s-subdomain/_search", target)
    authUser := "admin"
    authPassword := "StrongAdmin123!"

    // Lista para armazenar IPs únicos
    var listIP []string

    // Realiza a consulta ao Elasticsearch
    listIP, err := consulta(url, headers, authUser, authPassword)
    if err != nil {
        fmt.Printf("Erro durante a consulta: %v\n", err)
        os.Exit(1)
    }

    // Executa os comandos em paralelo
    err = parallel(target, listIP)
    if err != nil {
        fmt.Printf("Erro durante a execução paralela: %v\n", err)
        os.Exit(1)
    }
}

func consulta(url string, headers map[string]string, authUser, authPassword string) ([]string, error) {
    data := map[string]interface{}{
        "size": 10000,
    }
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, fmt.Errorf("Erro ao converter dados para JSON: %v", err)
    }

    req, err := http.NewRequest("GET", url, strings.NewReader(string(jsonData)))
    if err != nil {
        return nil, fmt.Errorf("Erro ao criar requisição HTTP: %v", err)
    }

    // Define os headers
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
        return nil, fmt.Errorf("Erro ao executar requisição HTTP: %v", err)
    }
    defer resp.Body.Close()

    // Lê a resposta
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("Erro ao ler o corpo da resposta: %v", err)
    }

    // Analisa o JSON
    var parseScan map[string]interface{}
    err = json.Unmarshal(body, &parseScan)
    if err != nil {
        return nil, fmt.Errorf("Erro ao analisar JSON: %v", err)
    }

    // Coleta IPs únicos
    ipSet := make(map[string]struct{})
    hits, ok := parseScan["hits"].(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("Erro ao analisar 'hits'")
    }
    hitsHits, ok := hits["hits"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("Erro ao analisar 'hits.hits'")
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
        serverIP, ok := source["server.ip"].(string)
        if !ok {
            continue
        }
        if _, exists := ipSet[serverIP]; !exists {
            ipSet[serverIP] = struct{}{}
        }
    }

    // Converte o conjunto em uma lista
    var listIP []string
    for ip := range ipSet {
        listIP = append(listIP, ip)
    }

    return listIP, nil
}

func parallel(target string, listIP []string) error {
    // Remove o arquivo de log anterior
    logFilePath := filepath.Join("/recon/data", target, "temp", "nmap_parallel.log")
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
    for _, ip := range listIP {
        cmdLine := fmt.Sprintf("/recon/program/scripts/nmap_parse %s %s\n", target, ip)
        _, err := file.WriteString(cmdLine)
        if err != nil {
            return fmt.Errorf("Erro ao escrever no arquivo de log: %v", err)
        }
    }

    fmt.Println("[+] PROCESSANDO NMAP \n")

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
