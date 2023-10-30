#!/bin/bash

i18n_dir="${I18N_DIR:-linotp/i18n}"
translations_dir="${TRANSLATIONS_DIR:-/translations}"

for file in "$i18n_dir"/*/LC_MESSAGES/linotp.po; do
    out_file=$(echo "$file" | sed 's/\.po$/\.mo/')
    msgfmt -o "$out_file" "$file"
done

mkdir -p "$translations_dir"
mv "$i18n_dir"/* "$translations_dir"