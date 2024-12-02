curl -XDELETE --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-subdomain
echo
curl -XDELETE --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-portscan
echo
curl -XDELETE --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-webenum
echo
curl -XDELETE --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-webvuln
echo
curl -XDELETE --insecure --user admin:'StrongAdmin123!' https://localhost:9200/$1-infravuln
