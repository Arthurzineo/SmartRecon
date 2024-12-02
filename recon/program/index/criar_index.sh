echo "[+] Criando index SUBDOMAIN"
echo
curl -XPUT --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-subdomain -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
		"@timestamp":{"type":"date"},
		"server.address": {"type":"keyword"},
		"server.domain": {"type":"keyword"},
                "server.nameserver": {"type":"keyword"},
		"server.ip": {"type":"ip"},
                "server.ipblock": {"type":"keyword"},
		"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo

echo "[+] Criando index PORT SCANNING"
echo
curl -XPUT --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-portscan -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
			"@timestamp":{"type":"date"},
			"server.address": {"type":"keyword"},
			"network.protocol": {"type":"keyword"},
			"server.ip": {"type":"ip"},
            		"server.port": {"type":"long"},
            		"server.ipblock": {"type":"keyword"},
            		"service.name": {"type":"keyword"},
			"service.state": {"type":"keyword"},
            		"application.version.number": { "type":"keyword"},
            		"network.transport": {"type":"keyword"},
      			"network.type": {"type":"keyword"},
			"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo

echo "[+] Criando index WEB ENUM"
echo
curl -XPUT --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-webenum -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
			"@timestamp":{"type":"date"},
			"server.address": {"type":"keyword"},
            		"server.domain": {"type":"keyword"},
			"server.ip": {"type":"ip"},
            		"server.port": {"type":"long"},
            		"network.protocol": {"type":"keyword"},
            		"url.path": {"type":"keyword"},
            		"http.response.status_code": {"type":"long"},
            		"url.original": {"type":"keyword"},
     			"url.full": {"type":"keyword"},
			"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo

echo "[+] Criando index WEB VULN"
echo

curl -XPUT --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-webvuln -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
			"@timestamp":{"type":"date"},
			"server.address": {"type":"keyword"},
            		"server.domain": {"type":"keyword"},
			"server.ip": {"type":"ip"},
            		"server.port": {"type":"long"},
            		"network.protocol": {"type":"keyword"},
            		"service.name": {"type":"keyword"},
            		"url.path": {"type":"keyword"},
            		"http.response.status_code": {"type":"long"},
            		"vulnerability.description": {"type":"keyword"},
            		"vulnerability.name": {"type":"keyword"},
            		"vulnerability.severity": {"type":"keyword"},
            		"url.original": {"type":"keyword"},
     			"url.full": {"type":"keyword"},
			"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo

echo "[+] Criando index INFRA VULN"
echo

curl -XPUT --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-infravuln -H "Content-Type: application/json" -d @- <<EOF
{
	"mappings":{
		"properties":{
			"@timestamp":{"type":"date"},
			"server.address": {"type":"keyword"},
			"server.ip": {"type":"ip"},
           		 "server.port": {"type":"long"},
            		"network.protocol": {"type":"keyword"},
            		"service.name": {"type":"keyword"},
            		"vulnerability.description": {"type":"keyword"},
            		"vulnerability.name": {"type":"keyword"},
            		"vulnerability.severity": {"type":"keyword"},
			"vulnerability.scanner.vendor": {"type":"keyword"}
		}
	}
}
EOF
echo
