#!/bin/bash
add_rule () {
        SET=$1
        iptables -t raw -C PREROUTING -m set --match-set $SET src -j DROP 2>/dev/null || \
        iptables -t raw -I PREROUTING -m set --match-set $SET src -j DROP
}

# Insert in reverse order (because -I inserts at top)
add_rule blk_phpdictionary
add_rule blk_botscout_7d
add_rule blk_sblam
add_rule blk_greensnow
add_rule blk_strongips
add_rule blk_dshield_30d
add_rule blk_spamhaus
