#!/bin/sh

PATH=/usr/bin:/usr/sbin

if [ -n "$TLS_CA_CERTS" ]; then
    cd /usr/local/share/ca-certificates
    echo "$TLS_CA_CERTS" \
	| sed '/^$/d' \
	| csplit --quiet --prefix=env_ --suffix-format="%02d.crt" \
		 --elide-empty-files - "/-----END CERTIFICATE-----/+1" "{*}"
fi

update-ca-certificates
