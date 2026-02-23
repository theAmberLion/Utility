## 1. Create a directory

`mkdir /BLOCKLISTS`

## 2. Copy files 

**create_ipsets.sh**, **inject_blocklists.sh**, and **update_blocklists.sh** into created directory

## 3. Make files executable

`chmod +x create_ipsets.sh`
`chmod +x inject_blocklists.sh`
`chmod +x update_blocklists.sh`

## 4. Create system service for injecting ipset-based rules into iptables RAW table

`nano /etc/systemd/system/inject_blocklists.service`
*...or whatever your systemd services path is*

with this content

```
[Unit]
Description=Inject Blocklist Rules into iptables RAW table
After=network.target ipset.service

[Service]
Type=oneshot
ExecStart=/BLOCKLIST/inject_blocklists.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Adjust <kbd>ExecStart=</kbd> with your own path, of you created directory.

After editing the service file, do not forget to reload:

`systemctl daemon-reload`

## 5. Create ipsets:
By running script via `./create_ipsets.sh` command 

## 6. Verify that ipsets are created:

`ipset list -terse`

## 7. Update the blocklists and populate the ipsets for the first time:

By running script via `./update_blocklists.sh` command 

## 8. Verify blocklists update log: 

`tail -n 50 /var/log/update-blocklists.log`

## 9. Verify ipsets again:

`ipset list -terse`
You should see that ipsets contain elements now:
`Number of entries:` row

## 10. Start and enable the service:

`systemctl enable inject_blocklists.service`
`systemctl start inject_blocklists.service`

## 11. Verify status:

`systemctl status inject_blocklists.service`
If some errors happened, then you will see output there.

## 12. Create scheduled task to update blocklists every morning
crontab -e
`0 6 * * * /BLOCKLIST/update_blklists.sh`

or nano /etc/crontab
`0 6 * * * root /BLOCKLIST/update_blklists.sh`

# That's it!

