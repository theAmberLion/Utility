{

:local WanIf "ether1"
:local ScriptOwner "user"

# Scripts

/system script
add dont-require-permissions=no name=Download_and_parse_firehol_spamhaus_drop \
    owner=$ScriptOwner policy=ftp,read,write,test source="# Script: update_spamhaus\
    _ROSv7 - https://iplists.firehol.org/\?ipset=spamhaus_drop\r\
    \n# The Spamhaus Don't Route Or Peer (DROP) lists consist of netblocks tha\
    t are leased or stolen by professional spam or cyber-crime operations, and\
    \_used for dissemination of malware, trojan downloaders, botnet controller\
    s, or other kinds of malicious activity. Processed by FireHOL.\r\
    \n\r\
    \n:local listName \"Blocklist_Spamhaus_DROP\"\r\
    \n:local url \"https://iplists.firehol.org/files/spamhaus_drop.netset\"\r\
    \n:local fileName \"spamhaus_drop.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https dst-path=\$fileName\r\
    \n\r\
    \n# 2. Wait for the file to be written\r\
    \n:delay 3s\r\
    \n\r\
    \n# 3. Process\r\
    \n:if ([/file find name=\$fileName] != \"\") do={\r\
    \n    :local fileContent [/file get \$fileName contents]\r\
    \n    :local contentLen [:len \$fileContent]\r\
    \n    \r\
    \n    # Only clear if we actually got data\r\
    \n    :if (\$contentLen > 0) do={\r\
    \n        /ip firewall address-list remove [find list=\$listName]\r\
    \n        \r\
    \n        :local lineEnd 0\r\
    \n        :local lineStart 0\r\
    \n        :local line \"\"\r\
    \n        \r\
    \n        :while (\$lineStart < \$contentLen) do={\r\
    \n            # Find the next newline\r\
    \n            :set lineEnd [:find \$fileContent \"\\n\" \$lineStart]\r\
    \n            \r\
    \n            # If no more newlines, grab until end of file\r\
    \n            :if ([:len \$lineEnd] = 0) do={ :set lineEnd \$contentLen }\
    \r\
    \n            \r\
    \n            # Extract the line\r\
    \n            :set line [:pick \$fileContent \$lineStart \$lineEnd]\r\
    \n            :set lineStart (\$lineEnd + 1)\r\
    \n            \r\
    \n            # Remove \\r (carriage return) for clean IP strings\r\
    \n            :local cleanLine \"\"\r\
    \n            :for i from=0 to=([:len \$line] - 1) do={\r\
    \n                :local char [:pick \$line \$i]\r\
    \n                :if (\$char != \"\\r\") do={ :set cleanLine (\$cleanLine\
    \_. \$char) }\r\
    \n            }\r\
    \n            \r\
    \n            # Filter: Ignore comments and empty lines\r\
    \n            :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"\
    #\") do={\r\
    \n                :do {\r\
    \n                    /ip firewall address-list add list=\$listName addres\
    s=\$cleanLine\r\
    \n                } on-error={ :put \"Error adding \$cleanLine\" }\r\
    \n            }\r\
    \n        }\r\
    \n        \r\
    \n        /file remove \$fileName\r\
    \n        :log info \"FireHOL Spamhaus DROP list updated.\"\r\
    \n    }\r\
    \n} else={\r\
    \n    :log error \"FireHOL Spamhaus DROP list download failed.\"\r\
    \n}"
add dont-require-permissions=no name=Download_and_parse_greensnow_co owner=\
    $ScriptOwner policy=ftp,read,write,test source="# greensnow_co_ROSv7 - chunked \
    read to handle >64KiB files\r\
    \n# GreenSnow is comparable with SpamHaus.org for attacks of any kind exce\
    pt for spam. Attacks / bruteforce that are monitored are: Scan Port, FTP, \
    POP3, mod_security, IMAP, SMTP, SSH, cPanel, etc. (https://greensnow.co/)\
    \r\
    \n \r\
    \n\r\
    \n:local listName \"Blocklist_Greensnow_co\"\r\
    \n:local url \"https://blocklist.greensnow.co/greensnow.txt\"\r\
    \n:local fileName \"greensnow_blocklist.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https check-certificate=no dst-path=\$fileNam\
    e\r\
    \n\r\
    \n# small delay to allow write to finish\r\
    \n:delay 2s\r\
    \n\r\
    \n:if ([/file find name=\$fileName] = \"\") do={\r\
    \n    :log error \"Greensnow blocklist download failed.\"\r\
    \n    :return\r\
    \n}\r\
    \n\r\
    \n# remove existing entries up-front (only if file exists and non-empty)\r\
    \n:local fsize [/file/get \$fileName size]\r\
    \n:if (\$fsize = 0) do={\r\
    \n    :log error \"Greensnow file empty (size 0).\"\r\
    \n    /file remove \$fileName\r\
    \n    :return\r\
    \n}\r\
    \n\r\
    \n# clear old list items\r\
    \n/ip firewall address-list remove [find list=\$listName]\r\
    \n:log info (\"Greensnow: fetched file size=\" . \$fsize . \" bytes\")\r\
    \n\r\
    \n# chunk-size: keep it small enough to avoid variable-size limits.\r\
    \n# 8k - 16k is a safe choice; you can raise toward 32768 if you know your\
    \_platform supports it.\r\
    \n:local chunkSize 16000\r\
    \n\r\
    \n:local offset 0\r\
    \n:local remainder \"\"\r\
    \n\r\
    \n:while (\$offset < \$fsize) do={\r\
    \n\r\
    \n    # read a chunk (returns an as-value map, with ->\"data\")\r\
    \n    :local chunkMap [/file/read file=\$fileName offset=\$offset chunk-si\
    ze=\$chunkSize as-value]\r\
    \n    :local data (\$chunkMap->\"data\")\r\
    \n\r\
    \n    # if read failed or returned nothing, break out to avoid infinite lo\
    op\r\
    \n    :if ([:len \$data] = 0) do={\r\
    \n        :log warning \"Greensnow: empty chunk read; stopping.\"\r\
    \n        break\r\
    \n    }\r\
    \n\r\
    \n    # advance offset by actual bytes read\r\
    \n    :set offset (\$offset + [:len \$data])\r\
    \n\r\
    \n    # combine remainder from previous chunk with current data\r\
    \n    :local combined (\$remainder . \$data)\r\
    \n    :set remainder \"\"\r\
    \n\r\
    \n    # parse completed lines from combined chunk\r\
    \n    :local pos [:find \$combined \"\\n\"]\r\
    \n    :while ([:len \$pos] > 0) do={\r\
    \n\r\
    \n        # take line up to newline (exclude newline)\r\
    \n        :local line [:pick \$combined 0 \$pos]\r\
    \n\r\
    \n        # drop that line (and newline) from combined\r\
    \n        :set combined [:pick \$combined (\$pos + 1) [:len \$combined]]\r\
    \n\r\
    \n        # strip CR if present\r\
    \n        :local cleanLine \"\"\r\
    \n        :for i from=0 to=([:len \$line] - 1) do={\r\
    \n            :local ch [:pick \$line \$i]\r\
    \n            :if (\$ch != \"\\r\") do={ :set cleanLine (\$cleanLine . \$c\
    h) }\r\
    \n        }\r\
    \n\r\
    \n        # skip empty lines and comments\r\
    \n        :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"#\")\
    \_do={\r\
    \n            :do {\r\
    \n                /ip firewall address-list add list=\$listName address=\$\
    cleanLine\r\
    \n            } on-error={ :put (\"Error adding \" . \$cleanLine) }\r\
    \n        }\r\
    \n\r\
    \n        # find next newline in the (now shorter) combined\r\
    \n        :set pos [:find \$combined \"\\n\"]\r\
    \n    }\r\
    \n\r\
    \n    # whatever remains in combined is a partial line (no terminating \\n\
    \_yet)\r\
    \n    :if ([:len \$combined] > 0) do={\r\
    \n        # keep as remainder and prepend to next chunk\r\
    \n        :set remainder \$combined\r\
    \n    }\r\
    \n}\r\
    \n\r\
    \n# after all chunks read, process a final remainder (if it doesn't end in\
    \_\\n)\r\
    \n:if ([:len \$remainder] > 0) do={\r\
    \n\r\
    \n    # strip trailing CR if present\r\
    \n    :local cleanLine \"\"\r\
    \n    :for i from=0 to=([:len \$remainder] - 1) do={\r\
    \n        :local ch [:pick \$remainder \$i]\r\
    \n        :if (\$ch != \"\\r\") do={ :set cleanLine (\$cleanLine . \$ch) }\
    \r\
    \n    }\r\
    \n\r\
    \n    # skip empty or commented final line\r\
    \n    :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"#\") do=\
    {\r\
    \n        :do {\r\
    \n            /ip firewall address-list add list=\$listName address=\$clea\
    nLine\r\
    \n        } on-error={ :put (\"Error adding final \" . \$cleanLine) }\r\
    \n    }\r\
    \n}\r\
    \n\r\
    \n# clean up\r\
    \n/file remove \$fileName\r\
    \n:log info \"Greensnow blocklist updated (chunked read).\"\r\
    \n"
add dont-require-permissions=no name=\
    Download_and_parse_firehol_botscout_7days owner=$ScriptOwner policy=\
    ftp,read,write,test source="# Script: update_botscout_7day_version_ROSv7 -\
    \_https://iplists.firehol.org/\?ipset=botscout_7d\r\
    \n# BotScout helps prevent automated web scripts, known as bots, from regi\
    stering on forums, polluting databases, spreading spam, and abusing forms \
    on web sites. They do this by tracking the names, IPs, and email addresses\
    \_that bots use and logging them as unique signatures for future reference\
    . This list is composed by FireHOL of the most recently-caught bots in 7 d\
    ays period.\r\
    \n\r\
    \n:local listName \"Blocklist_BotScout_7d\"\r\
    \n:local url \"https://iplists.firehol.org/files/botscout_7d.ipset\"\r\
    \n:local fileName \"botscout_7d.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https dst-path=\$fileName\r\
    \n\r\
    \n# 2. Wait for the file to be written\r\
    \n:delay 3s\r\
    \n\r\
    \n# 3. Process\r\
    \n:if ([/file find name=\$fileName] != \"\") do={\r\
    \n    :local fileContent [/file get \$fileName contents]\r\
    \n    :local contentLen [:len \$fileContent]\r\
    \n    \r\
    \n    # Only clear if we actually got data\r\
    \n    :if (\$contentLen > 0) do={\r\
    \n        /ip firewall address-list remove [find list=\$listName]\r\
    \n        \r\
    \n        :local lineEnd 0\r\
    \n        :local lineStart 0\r\
    \n        :local line \"\"\r\
    \n        \r\
    \n        :while (\$lineStart < \$contentLen) do={\r\
    \n            # Find the next newline\r\
    \n            :set lineEnd [:find \$fileContent \"\\n\" \$lineStart]\r\
    \n            \r\
    \n            # If no more newlines, grab until end of file\r\
    \n            :if ([:len \$lineEnd] = 0) do={ :set lineEnd \$contentLen }\
    \r\
    \n            \r\
    \n            # Extract the line\r\
    \n            :set line [:pick \$fileContent \$lineStart \$lineEnd]\r\
    \n            :set lineStart (\$lineEnd + 1)\r\
    \n            \r\
    \n            # Remove \\r (carriage return) for clean IP strings\r\
    \n            :local cleanLine \"\"\r\
    \n            :for i from=0 to=([:len \$line] - 1) do={\r\
    \n                :local char [:pick \$line \$i]\r\
    \n                :if (\$char != \"\\r\") do={ :set cleanLine (\$cleanLine\
    \_. \$char) }\r\
    \n            }\r\
    \n            \r\
    \n            # Filter: Ignore comments and empty lines\r\
    \n            :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"\
    #\") do={\r\
    \n                :do {\r\
    \n                    /ip firewall address-list add list=\$listName addres\
    s=\$cleanLine\r\
    \n                } on-error={ :put \"Error adding \$cleanLine\" }\r\
    \n            }\r\
    \n        }\r\
    \n        \r\
    \n        /file remove \$fileName\r\
    \n        :log info \"FireHOL BotScout_7d blocklist updated.\"\r\
    \n    }\r\
    \n} else={\r\
    \n    :log error \"FireHOL BotScout_7d blocklist download failed.\"\r\
    \n}"
add dont-require-permissions=no name=\
    Download_and_parse_firehol_php_dictionary_30d owner=$ScriptOwner policy=\
    ftp,read,write,test source="# Script: update_php_dictionary_30d_ROSv7 - ht\
    tps://iplists.firehol.org/\?ipset=php_dictionary_30d\r\
    \n# projecthoneypot.org HTTP directory attackers - last 30 days aggregatio\
    n (this list is composed by FireHOL using the RSS feed)\r\
    \n\r\
    \n:local listName \"Blocklist_php_dictionary_30d\"\r\
    \n:local url \"https://iplists.firehol.org/files/php_dictionary_30d.ipset\
    \"\r\
    \n:local fileName \"php_dictionary_30d.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https dst-path=\$fileName\r\
    \n\r\
    \n# 2. Wait for the file to be written\r\
    \n:delay 3s\r\
    \n\r\
    \n# 3. Process\r\
    \n:if ([/file find name=\$fileName] != \"\") do={\r\
    \n    :local fileContent [/file get \$fileName contents]\r\
    \n    :local contentLen [:len \$fileContent]\r\
    \n    \r\
    \n    # Only clear if we actually got data\r\
    \n    :if (\$contentLen > 0) do={\r\
    \n        /ip firewall address-list remove [find list=\$listName]\r\
    \n        \r\
    \n        :local lineEnd 0\r\
    \n        :local lineStart 0\r\
    \n        :local line \"\"\r\
    \n        \r\
    \n        :while (\$lineStart < \$contentLen) do={\r\
    \n            # Find the next newline\r\
    \n            :set lineEnd [:find \$fileContent \"\\n\" \$lineStart]\r\
    \n            \r\
    \n            # If no more newlines, grab until end of file\r\
    \n            :if ([:len \$lineEnd] = 0) do={ :set lineEnd \$contentLen }\
    \r\
    \n            \r\
    \n            # Extract the line\r\
    \n            :set line [:pick \$fileContent \$lineStart \$lineEnd]\r\
    \n            :set lineStart (\$lineEnd + 1)\r\
    \n            \r\
    \n            # Remove \\r (carriage return) for clean IP strings\r\
    \n            :local cleanLine \"\"\r\
    \n            :for i from=0 to=([:len \$line] - 1) do={\r\
    \n                :local char [:pick \$line \$i]\r\
    \n                :if (\$char != \"\\r\") do={ :set cleanLine (\$cleanLine\
    \_. \$char) }\r\
    \n            }\r\
    \n            \r\
    \n            # Filter: Ignore comments and empty lines\r\
    \n            :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"\
    #\") do={\r\
    \n                :do {\r\
    \n                    /ip firewall address-list add list=\$listName addres\
    s=\$cleanLine\r\
    \n                } on-error={ :put \"Error adding \$cleanLine\" }\r\
    \n            }\r\
    \n        }\r\
    \n        \r\
    \n        /file remove \$fileName\r\
    \n        :log info \"FireHOL php_dictionary_30d blocklist updated.\"\r\
    \n    }\r\
    \n} else={\r\
    \n    :log error \"FireHOL php_dictionary_30d blocklist download failed.\"\
    \r\
    \n}"
add dont-require-permissions=no name=2 \
    Download_and_parse_blocklist_de_strongIPs owner=$ScriptOwner policy=\
    ftp,read,write,test source="# Script: update_blocklist_de_strongips_ROSv7 \
    - https://www.blocklist.de/en/export.html\r\
    \n# This blocklist contains IPs which are older than 2 months and have mor\
    e than 5.000 attacks.\r\
    \n\r\
    \n:local listName \"Blocklist_de_strong_and_dshield_org_30d\"\r\
    \n:local url \"https://lists.blocklist.de/lists/strongips.txt\"\r\
    \n:local fileName \"blocklist_de_strongips.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https dst-path=\$fileName\r\
    \n\r\
    \n# 2. Wait for the file to be written\r\
    \n:delay 3s\r\
    \n\r\
    \n# 3. Process\r\
    \n:if ([/file find name=\$fileName] != \"\") do={\r\
    \n    :local fileContent [/file get \$fileName contents]\r\
    \n    :local contentLen [:len \$fileContent]\r\
    \n    \r\
    \n    # WE DO NOT CLEAR current address list. if we actually got data, we \
    add it to address list. The list is cleared by dshield script!\r\
    \n    :if (\$contentLen > 0) do={\r\
    \n                \r\
    \n        :local lineEnd 0\r\
    \n        :local lineStart 0\r\
    \n        :local line \"\"\r\
    \n        \r\
    \n        :while (\$lineStart < \$contentLen) do={\r\
    \n            # Find the next newline\r\
    \n            :set lineEnd [:find \$fileContent \"\\n\" \$lineStart]\r\
    \n            \r\
    \n            # If no more newlines, grab until end of file\r\
    \n            :if ([:len \$lineEnd] = 0) do={ :set lineEnd \$contentLen }\
    \r\
    \n            \r\
    \n            # Extract the line\r\
    \n            :set line [:pick \$fileContent \$lineStart \$lineEnd]\r\
    \n            :set lineStart (\$lineEnd + 1)\r\
    \n            \r\
    \n            # Remove \\r (carriage return) for clean IP strings\r\
    \n            :local cleanLine \"\"\r\
    \n            :for i from=0 to=([:len \$line] - 1) do={\r\
    \n                :local char [:pick \$line \$i]\r\
    \n                :if (\$char != \"\\r\") do={ :set cleanLine (\$cleanLine\
    \_. \$char) }\r\
    \n            }\r\
    \n            \r\
    \n            # Filter: Ignore comments and empty lines\r\
    \n            :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"\
    #\") do={\r\
    \n                :do {\r\
    \n                    /ip firewall address-list add list=\$listName addres\
    s=\$cleanLine\r\
    \n                } on-error={ :put \"Error adding \$cleanLine\" }\r\
    \n            }\r\
    \n        }\r\
    \n        \r\
    \n        /file remove \$fileName\r\
    \n        :log info \"blocklist.de strongIPs blocklist updated.\"\r\
    \n    }\r\
    \n} else={\r\
    \n    :log error \"blocklist.de strongIPs  blocklist download failed.\"\r\
    \n}"
add dont-require-permissions=no name=1 \
    Download_and_parse_firehol_dshield_org_30d owner=$ScriptOwner policy=\
    ftp,read,write,test source="# Script: update_blocklist_de_strongips_ROSv7 \
    - https://iplists.firehol.org/\?ipset=dshield_30d\r\
    \n# This blocklist is aggregated by FireHOL from DShield.org top 20 attack\
    ing class C (/24) subnets over last 30 days.\r\
    \n\r\
    \n:local listName \"Blocklist_de_strong_and_dshield_org_30d\"\r\
    \n:local url \"https://iplists.firehol.org/files/dshield_30d.netset\"\r\
    \n:local fileName \"dshield_org_30d.txt\"\r\
    \n\r\
    \n# 1. Download the file\r\
    \n/tool fetch url=\$url mode=https dst-path=\$fileName\r\
    \n\r\
    \n# 2. Wait for the file to be written\r\
    \n:delay 3s\r\
    \n\r\
    \n# 3. Process\r\
    \n:if ([/file find name=\$fileName] != \"\") do={\r\
    \n    :local fileContent [/file get \$fileName contents]\r\
    \n    :local contentLen [:len \$fileContent]\r\
    \n    \r\
    \n    # Only clear if we actually got data\r\
    \n    :if (\$contentLen > 0) do={\r\
    \n        /ip firewall address-list remove [find list=\$listName]\r\
    \n        \r\
    \n        :local lineEnd 0\r\
    \n        :local lineStart 0\r\
    \n        :local line \"\"\r\
    \n        \r\
    \n        :while (\$lineStart < \$contentLen) do={\r\
    \n            # Find the next newline\r\
    \n            :set lineEnd [:find \$fileContent \"\\n\" \$lineStart]\r\
    \n            \r\
    \n            # If no more newlines, grab until end of file\r\
    \n            :if ([:len \$lineEnd] = 0) do={ :set lineEnd \$contentLen }\
    \r\
    \n            \r\
    \n            # Extract the line\r\
    \n            :set line [:pick \$fileContent \$lineStart \$lineEnd]\r\
    \n            :set lineStart (\$lineEnd + 1)\r\
    \n            \r\
    \n            # Remove \\r (carriage return) for clean IP strings\r\
    \n            :local cleanLine \"\"\r\
    \n            :for i from=0 to=([:len \$line] - 1) do={\r\
    \n                :local char [:pick \$line \$i]\r\
    \n                :if (\$char != \"\\r\") do={ :set cleanLine (\$cleanLine\
    \_. \$char) }\r\
    \n            }\r\
    \n            \r\
    \n            # Filter: Ignore comments and empty lines\r\
    \n            :if ([:len \$cleanLine] > 0 && [:pick \$cleanLine 0 1] != \"\
    #\") do={\r\
    \n                :do {\r\
    \n                    /ip firewall address-list add list=\$listName addres\
    s=\$cleanLine\r\
    \n                } on-error={ :put \"Error adding \$cleanLine\" }\r\
    \n            }\r\
    \n        }\r\
    \n        \r\
    \n        /file remove \$fileName\r\
    \n        :log info \"FireHOL Dshield.org 30d blocklist updated.\"\r\
    \n    }\r\
    \n} else={\r\
    \n    :log error \"FireHOL Dshield.org 30d  blocklist download failed.\"\r\
    \n}"

# Schedulers to run scripts

/system scheduler
add disabled=yes interval=1w name=Update_firehol_spamhaus_drop_blocklist on-event=\
    "/system/script/run Download_and_parse_firehol_spamhaus_drop" policy=\
    ftp,read,write,test start-date=2026-02-16 start-time=05:50:00
add disabled=yes interval=1d name=Update_greensnow_co_blocklist on-event=\
    "/system/script/run Download_and_parse_greensnow_co" policy=\
    ftp,read,write,test start-date=2026-02-16 start-time=06:00:00
add disabled=yes interval=1d name=Update_firehol_botscout_7d_blocklist on-event=\
    "/system/script/run Download_and_parse_firehol_botscout_7days" policy=\
    ftp,read,write,test start-date=2026-02-16 start-time=06:15:00
add disabled=yes interval=1w name=Update_firehol_php_dictionary_30d_blocklist on-event=\
    "/system/script/run Download_and_parse_firehol_php_dictionary_30d" \
    policy=ftp,read,write,test start-date=2026-02-16 start-time=06:25:00
add disabled=yes interval=1w name=1 Update_firehol_dshield_org_30d_blocklist on-event=\
    "/system/script/run Download_and_parse_firehol_dshield_org_30d" policy=\
    ftp,read,write,test start-date=2026-02-16 start-time=06:30:00
add disabled=yes interval=1w name=2 Update_blocklist_de_strongIPs_blocklist on-event=\
    "/system/script/run Download_and_parse_blocklist_de_strongIPs" policy=\
    ftp,read,write,test start-date=2026-02-16 start-time=06:40:00

# Layer 7 patterns

/ip firewall layer7-protocol
add name=HTTP_Path_Directory_Traversal_patterns regexp="\\x2f\?(\\.\\.|\\.%2e|\
    \\.%252e|%%32%65|%32%65|%2e%2e%2f|%2e\\.|%252e\\.).*(%2f|%252f|\\x2f)((bin\
    (%2f|%252f|\\x2f)(bash|sh))|(etc(%2f|%252f|\\x2f)(passwd|shadow)))"
add name=HTTP_suspicious_and_malicious_user-agents regexp="user-agent:[ \\t\\r\
    \\n\\v\\f]+(libredtail|Uirusu\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|go-http-clien\
    t\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|Go-http-client|Tsunami\\x2f[0-9]\\.[0-9][\
    A-Za-z0-9]\?|python-requests\\x2f[0-9]\\.[0-9][0-9]\?|Python-urllib\\x2f[0\
    -9]\\.[0-9][0-9]\?|python-http|Process\\x2fimToken|hello world|hello, worl\
    d|.+crawler|Sogou Pic Spider\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|.+zgrab\\x2f[0\
    -9]\\.[A-Za-z0-9]|.+bingbot\\x2f[0-9]\\.[A-Za-z0-9].\?|Java\\x2f[0-9]\\.[A\
    -Za-z0-9].\?|axios\\x2f[0-9]\\.[A-Za-z0-9][0-9]\?|.+aiohttp\\x2f[0-9].[0-9\
    ][0-9]\?|Offline Explorer\\x2f[0-9].[0-9][0-9]\?|FreePBX-Scanner\\x2f[0-9]\
    \\.[0-9]|AsyncHttpClient|libwww-perl|Bull Miners)"
add name=HTTP_Command_execution_patterns regexp="cd%20\\x2f|cd[ \\t\\r\\n\\v\\\
    f]+\\x2f|cd\\+\\x2f|curl[ \\t\\r\\n\\v\\f]+|wget[ \\t\\r\\n\\v\\f]+|curl%2\
    0|wget%20|;wget\\+|chmod 777|chmod%20777|shell_exec|\\x2fbin\\x2fbash|\\x2\
    fbin\\x2fsh|rm\\+-rf\\+\\x2f|rm[ \\t\\r\\n\\v\\f]+-rf[ \\t\\r\\n\\v\\f]+\\\
    x2f|cmd=|\\x2fshell\\\?|cgi-bin\\x2fluci\\x2f;stok="
add name=HTTP_file_crawling_pattern regexp="get[ \\t\\r\\n\\v\\f]+.+\\x2f\?\\.\
    env|get[ \\t\\r\\n\\v\\f]+.+\\x2f\?\\.git\\x2f(config|credentials)|get[ \\\
    t\\r\\n\\v\\f]+.+\\x2fPHP\\x2feval-stdin.php|get[ \\t\\r\\n\\v\\f]+\\x2fad\
    min\\x2f(config\\.php|config)\r\
    \n"
add name=SIP_Bogus_User-Agents regexp=\
    "PolycomSoundPointIP|SIP.Scanner|Z 3\\.14\\.38765 rv2\\.8\\.."
add name=SMTP_bogus_EHLO_messages regexp="ehlo[ \\t\\r\\n\\v\\f]+user|ehlo[ \\\
    t\\r\\n\\v\\f]+admin|ehlo[ \\t\\r\\n\\v\\f]+win-c5h9jsrghtg|ehlo[ \\t\\r\\\
    n\\v\\f]+localhost|ehlo[ \\t\\r\\n\\v\\f]+domain|ehlo[ \\t\\r\\n\\v\\f]+95\
    \\.65\\.73\\.|ehlo[ \\t\\r\\n\\v\\f]+127.0.0."

# Address Lists

/ip firewall address-list
add address=35.203.210.0/23 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=144.86.173.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=147.185.132.0/23 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=162.216.149.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=162.216.150.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=172.105.147.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=198.235.24.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=205.210.31.0/24 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=216.25.88.0/21 comment=\
    "PaloAlto Cortex Xpanse Scanners (CFAA-compliant)" list=Green_scanners
add address=scan.cypex.ai comment=https://cypex.ai/scanning list=\
    Green_scanners
add address=66.132.159.0/24 comment=https://censys.com/ list=Green_scanners
add address=162.142.125.0/24 comment=https://censys.com/ list=Green_scanners
add address=167.94.138.0/24 comment=https://censys.com/ list=Green_scanners
add address=167.94.145.0/24 comment=https://censys.com/ list=Green_scanners
add address=167.94.146.0/24 comment=https://censys.com/ list=Green_scanners
add address=167.248.133.0/24 comment=https://censys.com/ list=Green_scanners
add address=199.45.154.0/24 comment=https://censys.com/ list=Green_scanners
add address=199.45.155.0/24 comment=https://censys.com/ list=Green_scanners
add address=206.168.34.0/24 comment=https://censys.com/ list=Green_scanners
add address=206.168.35.0/24 comment=https://censys.com/ list=Green_scanners
add address=109.191.134.77 list=BlackList_manual

# Mangle rules

/ip firewall mangle
add disabled=yes action=add-src-to-address-list address-list=Abusers_Http_Smtp \
    address-list-timeout=2d chain=prerouting comment="<HTTP> detect HttpComman\
    dExecutionAttempt and add Source IP address to [Abusers_Http] address list\
    \_for 48h" dst-port=80 in-interface=$WanIf layer7-protocol=\
    HTTP_Command_execution_patterns log=yes log-prefix=\
    BanHttpCommandExecutionAttempt protocol=tcp src-address-list=\
    !Green_scanners
add disabled=yes action=add-src-to-address-list address-list=Abusers_Http_Smtp \
    address-list-timeout=2d chain=prerouting comment="<HTTP> Detect Suspicious\
    \_User-Agent and add Source IP address to [Abusers_Http] address list for \
    48h" dst-port=80 in-interface=$WanIf layer7-protocol=\
    HTTP_suspicious_and_malicious_user-agents log=yes log-prefix=\
    BanHttpSuspiciousUserAgent protocol=tcp src-address-list=!Green_scanners
add disabled=yes action=add-src-to-address-list address-list=Abusers_Http_Smtp \
    address-list-timeout=2d chain=prerouting comment=\
    "<HTTP> Detect File crawlers" dst-port=80 in-interface=$WanIf \
    layer7-protocol=HTTP_file_crawling_pattern log=yes log-prefix=\
    Ban-HttpEnv&GitCrawler protocol=tcp src-address-list=!Green_scanners
add disabled=yes action=add-src-to-address-list address-list=Abusers_Http_Smtp \
    address-list-timeout=2d chain=prerouting comment="<SMTP> Detect bogus EHLO\
    \_messages and add abuser to [Abusers_Smtp] address list for 24 hours" \
    dst-port=25,587 in-interface=$WanIf layer7-protocol=\
    SMTP_bogus_EHLO_messages log=yes log-prefix=BanSmtpAbuser protocol=tcp \
    src-address-list=!Green_scanners
add disabled=yes action=add-src-to-address-list address-list=Abusers_Http_Smtp \
    address-list-timeout=2d chain=prerouting comment="<HTTP> detect HttpPathTr\
    aversalAttempt and add Source IP address to [Abusers_Http] address list fo\
    r 48h" dst-port=80 in-interface=$WanIf layer7-protocol=\
    HTTP_Path_Directory_Traversal_patterns log=yes log-prefix=\
    Ban-HttpPathTraversalAttempt protocol=tcp src-address-list=\
    !Green_scanners
add disabled=yes action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=12h chain=prerouting comment="<SIP> Detect abusers ba\
    sed on User-Agent and add to [Abusers_Blacklist] address list for 12 hours\
    " dst-port=5060 in-interface=$WanIf layer7-protocol=\
    SIP_Bogus_User-Agents log=yes log-prefix=BanSipSuspiciousUA protocol=udp

# RAW rules

/ip firewall raw
add disabled=yes action=drop chain=prerouting comment="[FireHOL_spamhaus_DROP_Blocklist]" \
    in-interface=$WanIf src-address-list=Blocklist_Spamhaus_DROP
add disabled=yes action=drop chain=prerouting comment="[Blocklist.de strongIPs blocklist an\
    d Dshield.org top attackers blocklist]" in-interface=$WanIf \
    src-address-list=Blocklist_de_strong_and_dshield_org_30d
add disabled=yes action=drop chain=prerouting comment="[greensnow.co_Blocklist]" \
    in-interface=$WanIf src-address-list=Blocklist_Greensnow_co
add disabled=yes action=drop chain=prerouting comment="[FireHOL_BotScout_7days_Blocklist]" \
    in-interface=$WanIf src-address-list=Blocklist_BotScout_7d
add disabled=yes action=drop chain=prerouting comment=\
    "[FireHOL_php_dictionary_30days_Blocklist]" in-interface=$WanIf \
    src-address-list=Blocklist_php_dictionary_30d
add action=drop chain=prerouting comment="[Abusers_Blacklist]- drop detected p\
    ort scanners, crawlers and other abusers" in-interface=$WanIf \
    src-address-list=Abusers_Blacklist
add action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=1d chain=prerouting comment="PortScanners (TCP) - if \
    source address is already suspect in [PortScanTCP-Suspect] address list an\
    d 2nd attempt is detected, then add to [Abusers_Blacklist] address list fo\
    r 24h." dst-port=\
    21,23,110,135,139,143,389,445,1433,1521,3306,3389,5432,5900,11211 \
    in-interface=$WanIf log-prefix=BanPortScanTCP protocol=tcp \
    src-address-list=PortScanTCP-Suspect
add action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=1d chain=prerouting comment="PortScanners (UDP) - if \
    source address is already suspect in [PortScanUDP-Suspect] address list an\
    d 2nd attempt is detected, then add to [Abusers_Blacklist] address list fo\
    r 24h." dst-port=67,69,161,514,1194,1900,11211 in-interface=$WanIf \
    log-prefix=BanPortScanUDP protocol=udp src-address-list=\
    PortScanUDP-Suspect
add action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=1d chain=prerouting comment="PortScanners (UDP5060) -\
    \_if source address is already suspect in [PortScanUDP-Suspect] address li\
    st and 2nd attempt is detected, then add to [Abusers_Blacklist] address li\
    st for 24h." dst-port=5060 in-interface=$WanIf log-prefix=\
    BanPortScanUDP5060 protocol=udp src-address-list=PortScanUDP-Suspect
add action=add-src-to-address-list address-list=PortScanTCP-Suspect \
    address-list-timeout=5m chain=prerouting comment="PortScanners (TCP) - det\
    ect 1st attempt and add Source IP address to [PortScanTCP-Suspect] address\
    \_list for 5m" dst-port=\
    21,23,110,135,139,143,389,445,1433,1521,3306,3389,5432,5900,11211 \
    in-interface=$WanIf log-prefix=PortScanTCP-suspect protocol=tcp
add action=add-src-to-address-list address-list=PortScanUDP-Suspect \
    address-list-timeout=5m chain=prerouting comment="PortScanners (UDP) - det\
    ect 1st attempt and add Source IP address to [PortScanUDP-Suspect] address\
    \_list for 5m" dst-port=67,69,161,514,1194,1900,11211 in-interface=\
    $WanIf protocol=udp
add action=add-src-to-address-list address-list=PortScanUDP-Suspect \
    address-list-timeout=5m chain=prerouting comment="PortScanners (UDP 5060) \
    - detect 1st attempt of SIP scan and add Source IP address to [PortScanUDP\
    -Suspect] address list for 5m" dst-address=!95.65.73.89 dst-port=5060 \
    in-interface=$WanIf protocol=udp
add action=drop chain=prerouting comment="PortScanners (TCP) - explicit drop" \
    dst-port=\
    21,23,110,135,139,143,389,445,1433,1521,3306,3389,5432,5900,11211 \
    in-interface=$WanIf protocol=tcp
add action=drop chain=prerouting comment="PortScanners (UDP) - explicit drop" \
    dst-port=67,69,161,514,1194,1900,11211 in-interface=$WanIf protocol=udp
add action=accept chain=prerouting comment="SYN abusers protection (it's OK if\
    \_less than 20 SYN packets in 60 seconds from same ip address)" \
    dst-limit=20/1m,1,src-address/1m dst-port=8291,8728 in-interface=$WanIf \
    protocol=tcp tcp-flags=syn
add action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=1h chain=prerouting comment="SYN abusers protection (\
    if more  than 20 SYN packets in 60 seconds from same ip address - add  to \
    [Abusers_Blacklist] address list for 1 hour" dst-port=8291,8728 \
    in-interface=$WanIf log-prefix=BanSynAbuser protocol=tcp tcp-flags=syn
add action=accept chain=prerouting comment="ICMP abusers protection (it's OK i\
    f less than 4 ICMP packets in a second from same ip address)" dst-limit=\
    4,1,src-address/5s in-interface=$WanIf protocol=icmp
add action=add-src-to-address-list address-list=Abusers_Blacklist \
    address-list-timeout=1h chain=prerouting comment="ICMP abusers protection \
    (if more  than 4 ICMP packets in a second from same ip address - add  to [\
    Abusers_Blacklist] address list for 1 hour" in-interface=$WanIf \
    log-prefix=BanICMPAbuser protocol=icmp
add disabled=yes action=drop chain=prerouting comment="[Abusers_Http_Smtp] - drop traffic f\
    rom Http and Smtp crawlers and exploiters, detected at mangle stage" \
    in-interface=$WanIf src-address-list=Abusers_Http_Smtp
add action=drop chain=prerouting comment=\
    "[BlackList-Winbox] - drop traffic of winbox bruteforcers" in-interface=\
    $WanIf src-address-list=BlackList-Winbox
add action=drop chain=prerouting comment=\
    "[BlackList_manual] - drop traffic of manual blacklist" in-interface=\
    $WanIf src-address-list=BlackList_manual
add disabled=yes action=drop chain=prerouting comment="Drop DNS requests to WAN in order to\
    \_protect from DNS amplification attacks" dst-port=53 in-interface=\
    $WanIf protocol=udp
add disabled=yes action=drop chain=prerouting dst-port=53 in-interface=$WanIf protocol=\
    tcp

# Filter rules

/ip firewall filter
add disabled=yes action=drop chain=forward comment="[Abusers_Http_Smtp] - drop requests fro\
    m Http and Smtp crawlers and exploiters, detected at mangle level" \
    in-interface=$WanIf src-address-list=Abusers_Http_Smtp
add action=add-dst-to-address-list address-list=BlackList-Winbox \
    address-list-timeout=1d chain=output comment="Detect Winbox 2nd failed Att\
    empt --> add to address list [BlackList-Winbox] for 24h" content=\
    "invalid user name or password" dst-address-list=LoginFailure01 log=yes \
    log-prefix=BanWinboxAbuser protocol=tcp src-port=8291,8728
add action=add-dst-to-address-list address-list=LoginFailure01 \
    address-list-timeout=1h chain=output comment="Detect Winbox 1st failed Att\
    empt --> add to address list [LoginFailure01]" content=\
    "invalid user name or password" protocol=tcp src-port=8291,8728
add disabled=yes action=drop chain=forward comment=\
    "do not allow reply to Http and Smtp abusers" dst-address-list=\
    Abusers_Http_Smtp log-prefix=DropHttpSmtpReply out-interface=$WanIf

/
}