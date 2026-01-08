#!/usr/bin/env bash

download_as_browser() {
    local url="$1"
    local output="$2"

    if [ -z "$output" ]; then
        output=$(basename "$url")
    fi

    echo "Downloading: $url -> $output"

    curl --proxy http://127.0.0.1:4141 -f -L \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
        -H "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7" \
        -H "Cache-Control: max-age=0" \
        -H "Connection: keep-alive" \
        -H "Sec-CH-UA: \"Not A(Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"" \
        -H "Sec-CH-UA-Mobile: ?0" \
        -H "Sec-CH-UA-Platform: \"Windows\"" \
        -H "Sec-Fetch-Dest: document" \
        -H "Sec-Fetch-Mode: navigate" \
        -H "Sec-Fetch-Site: none" \
        -H "Sec-Fetch-User: ?1" \
        -H "Upgrade-Insecure-Requests: 1" \
        --compressed \
        -o "$output" \
        "$url"
}

download_as_browser https://publicsuffix.org/list/public_suffix_list.dat
download_as_browser https://secure.fanboy.co.nz/fanboy-cookiemonster.txt
download_as_browser https://easylist-downloads.adblockplus.org/easyprivacy.txt
download_as_browser https://easylist-downloads.adblockplus.org/easylist.txt
