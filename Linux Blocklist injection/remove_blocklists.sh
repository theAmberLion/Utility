#!/bin/bash

TABLE=raw
CHAIN=PREROUTING

# Remove rules referencing your ipsets
iptables -t $TABLE -D $CHAIN -m set --match-set blk_spamhaus src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_dshield_30d src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_strongips src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_greensnow src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_sblam src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_botscout_7d src -j DROP 2>/dev/null
iptables -t $TABLE -D $CHAIN -m set --match-set blk_phpdictionary src -j DROP 2>/dev/null
