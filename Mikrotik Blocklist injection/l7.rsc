# 2026-02-23 09:59:40 by RouterOS 7.20.2

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
    ][0-9]\?|Offline Explorer\\x2f[0-9].[0-9][0-9]\?|FreePBX-Scanner/x2f[0-9]\
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


/ip firewall layer7-protocol
add name=HTTP_Path_Directory_Traversal_patterns regexp="\\x2f\?(\\.\\.|\\.%2e|\\.%252e|%%32%65|%32%65|%2e%2e%2f|%2e\\.|%252e\\.).*(%2f|%252f|\\x2f)((bin(%2f|%252f|\\x2f)(bash|sh))|(etc(%2f|%252f|\\x2f)(passwd|shadow)))"
add name=HTTP_suspicious_and_malicious_user-agents regexp="user-agent:[ \\t\\r\\n\\v\\f]+(libredtail|Uirusu\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|go-http-client\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|Go-http-client|Tsunami\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|python-requests\\x2f[0-9]\\.[0-9][0-9]\?|Python-urllib\\x2f[0-9]\\.[0-9][0-9]\?|python-http|Process\\x2fimToken|hello world|hello, world|.+cr    awler|Sogou Pic Spider\\x2f[0-9]\\.[0-9][A-Za-z0-9]\?|.+zgrab\\x2f[0-9]\\.[A-Za-z0-9]|.+bingbot\\x2f[0-9]\\.[A-Za-z0-9].\?|Java\\x2f[0-9]\\.[A-Za-z0-9].\?|axios\\x2f[0-9]\\.[A-Za-z0-9][0-9]\?|.+aiohttp\\x2f[0-9].[0-9][0-9]\?|Offline Explorer\\x2f[0-9].[0-9][0-9]\?|FreePBX-Scanner/x2f[0-9]\\.[0-9]|AsyncHttpClient|libwww-perl|Bull Miners)"
add name=HTTP_Command_execution_patterns regexp="cd%20\\x2f|cd[ \\t\\r\\n\\v\\f]+\\x2f|cd\\+\\x2f|curl[ \\t\\r\\n\\v\\f]+|wget[ \\t\\r\\n\\v\\f]+|curl%20|wget%20|;wget\\+|chmod 777|chmod%20777|shell_exec|\\x2fbin\\x2fbash|\\x2fbin\\x2fsh|rm\\+-rf\\+\\x2f|rm[ \\t\\r\\n\\v\\f]+-rf[ \\t\\r\\n\\v\\f]+\\x2f|cmd=|\\x2fshell\\\?|cgi-bin\\x2fluci\\x2f;stok="
add name=HTTP_file_crawling_pattern regexp="get[ \\t\\r\\n\\v\\f]+.+\\x2f\?\\.env|get[ \\t\\r\\n\\v\\f]+.+\\x2f\?\\.git\\x2f(config|credentials)|get[ \\t\\r\\n\\v\\f]+.+\\x2fPHP\\x2feval-stdin.php|get[ \\t\\r\\n\\v\\f]+\\x2fadmin\\x2f(config\\.php|config)\r\n"
add name=SIP_Bogus_User-Agents regexp="PolycomSoundPointIP|SIP.Scanner|Z 3\\.14\\.38765 rv2\\.8\\.."
add name=SMTP_bogus_EHLO_messages regexp="ehlo[ \\t\\r\\n\\v\\f]+user|ehlo[ \\t\\r\\n\\v\\f]+admin|ehlo[ \\t\\r\\n\\v\\f]+win-c5h9jsrghtg|ehlo[ \\t\\r\\n\\v\\f]+localhost|ehlo[ \\t\\r\\n\\v\\f]+domain|ehlo[ \\t\\r\\n\\v\\f]+95\\.65\\.73\\.|ehlo[ \\t\\r\\n\\v\\f]+127.0.0."
