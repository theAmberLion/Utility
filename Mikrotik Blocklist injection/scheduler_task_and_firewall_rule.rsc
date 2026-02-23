/system scheduler
add interval=1d name=Update_greensnow_co_blocklist on-event="/system/script/run Download_and_parse_greensnow_co" policy=ftp,read,write,test start-date=2026-02-16 start-time=06:00:00

add action=drop chain=prerouting comment="[greensnow.co_Blocklist]" in-interface=eth1-WAN src-address-list=Blocklist_Greensnow_co
