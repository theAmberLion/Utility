#!/bin/bash

#set -o errexit
#set -o pipefail
#set -o nounset

LOGFILE="/var/log/update-blacklists.log"
MIN_ENTRIES=10  # minimum number of entries to allow a swap

log() {
    /usr/bin/echo "$(date '+%F %T') - $1" >> "$LOGFILE"
}

# Download feed safely
fetch_feed() {
    local URL=$1
    local OUTFILE=$2

    if ! /usr/local/bin/curl -fsSL --connect-timeout 15 --max-time 60 "$URL" -o "$OUTFILE"; then
        log "ERROR: Failed to download $URL"
        return 1
    fi

    # Reject HTML responses (Cloudflare block, error pages)
    if /usr/bin/grep -qi "<html" "$OUTFILE"; then
        log "ERROR: HTML received instead of feed from $URL"
        return 1
    fi

    return 0
}

# Update an ipset with a feed
update_set() {
    local NAME=$1
    local URL=$2
    local TYPE=$3   # json | plain

    local TMP="${NAME}_tmp"
    local WORKFILE="/tmp/${NAME}.feed"

    log "Updating $NAME from $URL"

    if ! fetch_feed "$URL" "$WORKFILE"; then
        log "Skipping $NAME due to download error"
        return 1
    fi

    # Create temporary set
    /usr/sbin/ipset create "$TMP" hash:net family inet hashsize 8192 maxelem 30000 2>/dev/null || true

    # Parse feed and populate TMP
    if [ "$TYPE" = "json" ]; then
        # Spamhaus NDJSON parser
        /usr/bin/jq -r '.cidr' "$WORKFILE" 2>/dev/null \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' \
        | while read -r net; do
            /usr/sbin/ipset add "$TMP" "$net" 2>/dev/null
        done
    else
        # Plain text feeds
        /usr/bin/grep -v '^#' "$WORKFILE" \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' \
        | while read -r net; do
            /usr/sbin/ipset add "$TMP" "$net" 2>/dev/null
        done
    fi

    # Count entries safely
    local COUNT
    COUNT=$(/usr/sbin/ipset list "$TMP" 2>/dev/null | awk -F': ' '/Number of entries/ {print $2}')

    if [ -z "$COUNT" ] || [ "$COUNT" -lt "$MIN_ENTRIES" ]; then
        log "ERROR: $NAME has too few entries ($COUNT). Swap aborted."
        /usr/sbin/ipset destroy "$TMP" 2>/dev/null || true
        return 1
    fi

    # Create main set if not exists
    if ! /usr/sbin/ipset list "$NAME" >/dev/null 2>&1; then
        /usr/sbin/ipset create "$NAME" hash:net family inet hashsize 8192 maxelem 30000
    fi

    # Atomic swap
    /usr/sbin/ipset swap "$TMP" "$NAME"
    /usr/sbin/ipset destroy "$TMP"

    log "SUCCESS: $NAME updated with $COUNT entries"
}

# ---------------- FEEDS ----------------

# 1. Spamhaus DROP v4 NDJSON
update_set blk_spamhaus \
"https://www.spamhaus.org/drop/drop_v4.json" \
json

# 2. FireHOL dshield 30d
update_set blk_dshield_30d \
"https://iplists.firehol.org/files/dshield_30d.netset" \
plain

# 3. blocklist.de strongips
update_set blk_strongips \
"https://lists.blocklist.de/lists/strongips.txt" \
plain

# 4. GreenSnow.co
update_set blk_greensnow \
"https://blocklist.greensnow.co/greensnow.txt" \
plain

# 5. Sblam.com
update_set blk_sblam \
"https://sblam.com/blacklist.txt" \
plain

# 6. FireHOL botscout 7d
update_set blk_botscout_7d \
"https://iplists.firehol.org/files/botscout_7d.ipset" \
plain

# 7. FireHOL php_dictionary 30d
update_set blk_phpdictionary \
"https://iplists.firehol.org/files/php_dictionary_30d.ipset" \
plain

log "All feeds processed."
