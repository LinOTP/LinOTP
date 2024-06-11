#!/bin/sh

PATH=/usr/bin:/usr/sbin

if [ -n "$TLS_CA_CERTS" ]; then
    cd /usr/local/share/ca-certificates
    # Note the two separate `sed` calls in the command below; if we
    # did both operations in the same `sed`, then `foo\n\nbar` in the
    # input would lead to an empty line in the output even though
    # we're trying to get rid of those. (We need the newline
    # substitution because Podman/Docker `--env-file` files don't
    # allow newlines in environment variable values, which interferes
    # with the PEM format used for certificates - hence we write
    # newlines as "backslash followed by lowercase n" to the file and
    # convert these back to newlines here. (You may wonder why we
    # don't simply say `echo -e`. The answer is that `echo -e` does
    # all sorts of other substitutions which we may not want done.)

    echo "$TLS_CA_CERTS" \
	| sed 's/\\n/\n/g' \
	| sed '/^$/d' \
	| csplit --quiet --prefix=env_ --suffix-format="%02d.crt" \
		 --elide-empty-files - "/-----END CERTIFICATE-----/+1" "{*}"
fi

update-ca-certificates
