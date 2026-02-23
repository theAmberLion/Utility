# greensnow_co ROuterOS v7 - chunked read to handle >64KiB files
# GreenSnow is comparable with SpamHaus.org for attacks of any kind except for spam. Attacks / bruteforce that are monitored are: Scan Port, FTP, POP3, mod_security, IMAP, SMTP, SSH, cPanel, etc. (https://greensnow.co/)
 

:local listName "Blocklist_Greensnow_co"
:local url "https://blocklist.greensnow.co/greensnow.txt"
:local fileName "greensnow_blocklist.txt"

# 1. Download the file
/tool fetch url=$url mode=https check-certificate=no dst-path=$fileName

# small delay to allow write to finish
:delay 2s

:if ([/file find name=$fileName] = "") do={
    :log error "Greensnow blocklist download failed."
    :return
}

# remove existing entries up-front (only if file exists and non-empty)
:local fsize [/file/get $fileName size]
:if ($fsize = 0) do={
    :log error "Greensnow file empty (size 0)."
    /file remove $fileName
    :return
}

# clear old list items
/ip firewall address-list remove [find list=$listName]
:log info ("Greensnow: fetched file size=" . $fsize . " bytes")

# chunk-size: keep it small enough to avoid variable-size limits.
# 8k - 16k is a safe choice; you can raise toward 32768 if you know your platform supports it.
:local chunkSize 16000

:local offset 0
:local remainder ""

:while ($offset < $fsize) do={

    # read a chunk (returns an as-value map, with ->"data")
    :local chunkMap [/file/read file=$fileName offset=$offset chunk-size=$chunkSize as-value]
    :local data ($chunkMap->"data")

    # if read failed or returned nothing, break out to avoid infinite loop
    :if ([:len $data] = 0) do={
        :log warning "Greensnow: empty chunk read; stopping."
        break
    }

    # advance offset by actual bytes read
    :set offset ($offset + [:len $data])

    # combine remainder from previous chunk with current data
    :local combined ($remainder . $data)
    :set remainder ""

    # parse completed lines from combined chunk
    :local pos [:find $combined "\n"]
    :while ([:len $pos] > 0) do={

        # take line up to newline (exclude newline)
        :local line [:pick $combined 0 $pos]

        # drop that line (and newline) from combined
        :set combined [:pick $combined ($pos + 1) [:len $combined]]

        # strip CR if present
        :local cleanLine ""
        :for i from=0 to=([:len $line] - 1) do={
            :local ch [:pick $line $i]
            :if ($ch != "\r") do={ :set cleanLine ($cleanLine . $ch) }
        }

        # skip empty lines and comments
        :if ([:len $cleanLine] > 0 && [:pick $cleanLine 0 1] != "#") do={
            :do {
                /ip firewall address-list add list=$listName address=$cleanLine
            } on-error={ :put ("Error adding " . $cleanLine) }
        }

        # find next newline in the (now shorter) combined
        :set pos [:find $combined "\n"]
    }

    # whatever remains in combined is a partial line (no terminating \n yet)
    :if ([:len $combined] > 0) do={
        # keep as remainder and prepend to next chunk
        :set remainder $combined
    }
}

# after all chunks read, process a final remainder (if it doesn't end in \n)
:if ([:len $remainder] > 0) do={

    # strip trailing CR if present
    :local cleanLine ""
    :for i from=0 to=([:len $remainder] - 1) do={
        :local ch [:pick $remainder $i]
        :if ($ch != "\r") do={ :set cleanLine ($cleanLine . $ch) }
    }

    # skip empty or commented final line
    :if ([:len $cleanLine] > 0 && [:pick $cleanLine 0 1] != "#") do={
        :do {
            /ip firewall address-list add list=$listName address=$cleanLine
        } on-error={ :put ("Error adding final " . $cleanLine) }
    }
}

# clean up
/file remove $fileName
:log info "Greensnow blocklist updated (chunked read)."
