# https://www.spamhaus.org/drop/drop_v4.json

ipset create blk_spamhaus hash:net family inet hashsize 4096 maxelem 20000


# https://iplists.firehol.org/?ipset=dshield_30d

ipset create blk_dshield_30d hash:net family inet hashsize 8192 maxelem 30000


# https://lists.blocklist.de/lists/strongips.txt

ipset create blk_strongips hash:net family inet hashsize 8192 maxelem 30000


# https://blocklist.greensnow.co/greensnow.txt

ipset create blk_greensnow hash:net family inet hashsize 8192 maxelem 30000


# https://sblam.com/blacklist.txt

ipset create blk_sblam hash:net family inet hashsize 8192 maxelem 30000


# https://iplists.firehol.org/files/botscout_7d.ipset

ipset create blk_botscout_7d hash:net family inet hashsize 8192 maxelem 30000


# https://iplists.firehol.org/?ipset=php_dictionary_30d

ipset create blk_phpdictionary hash:net family inet hashsize 8192 maxelem 30000

# Don't forget to
#
# mkdir /etc/ipset/
# ipset save > /etc/ipset/ipset
# 
# after
