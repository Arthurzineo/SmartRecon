package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 3 {
		fmt.Println("Uso: programa <target> <domain>")
		os.Exit(1)
	}

	target := os.Args[1]
	domain := os.Args[2]

	parallel(target, domain)
}

func parallel(target, domain string) {
	// Remove o arquivo de log anterior, se existir
	logFilePath := filepath.Join("/recon/data", target, "temp", "subdomain_parallel.log")
	os.Remove(logFilePath)

	// Cria o diretório temp se não existir
	tempDir := filepath.Join("/recon/data", target, "temp")
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		fmt.Printf("Erro ao criar o diretório temp: %v\n", err)
		return
	}

	// Abre o arquivo de log para escrita
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao abrir o arquivo de log: %v\n", err)
		return
	}
	defer file.Close()

	// Escreve os comandos no arquivo
	commands := []string{
		fmt.Sprintf("/recon/program/scripts/assetfinder_parse %s %s", target, domain),
		fmt.Sprintf("/recon/program/scripts/subfinder_parse %s %s", target, domain),
		fmt.Sprintf("/recon/program/scripts/sublist3r_parse %s %s", target, domain),
	}

	for _, cmd := range commands {
		_, err := file.WriteString(cmd + "\n")
		if err != nil {
			fmt.Printf("Erro ao escrever no arquivo de log: %v\n", err)
			return
		}
	}

	fmt.Println("[+] PROCESSANDO SUBDOMAIN \n")

	// Executa o comando 'cat subdomain_parallel.log | parallel -u'
	cmdStr := fmt.Sprintf("cat %s | parallel -u", logFilePath)
	cmd := exec.Command("bash", "-c", cmdStr)

	// Redireciona a saída para o console
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
	}
}
