# Suricata setup — IDS-01 (192.168.56.11)

## 1. Install
```
sudo apt update
sudo apt install -y suricata
```

## 2. VirtualBox adapter (required, done on the host, not inside the VM)
IDS-01 → Settings → Network → Adapter 2 (host-only) → Advanced →
**Promiscuous Mode: Allow All**.
Without this, IDS-01 only sees its own traffic and will never see the
port scan traffic between KALI-ATK01 and the other targets.

## 3. Add the lab rule
```
sudo cp local.rules /etc/suricata/rules/local.rules
```
Edit `/etc/suricata/suricata.yaml`:
```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - local.rules
```

## 4. Set the monitored interface and HOME_NET
In `/etc/suricata/suricata.yaml`:
```yaml
af-packet:
  - interface: enp0s8   # confirm the host-only interface name with `ip a`

vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"
```

## 5. Enable eve.json output
Confirm in `/etc/suricata/suricata.yaml` under `outputs:`:
```yaml
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns
        - http
```

## 6. Start and verify
```
sudo suricata-update          # optional: pulls ET Open ruleset, not required by this project
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/eve.json
```

## 7. Test the rule before the real simulation
From any other lab VM:
```
sudo nmap -sS -p 1-100 -T4 192.168.56.11
```
Confirm an `"alert"` entry with `"signature_id":1000001` appears in
`/var/log/suricata/eve.json` within a few seconds.

## 8. Enable Filebeat's suricata module
Only after confirming step 7, follow the setup commands at the top of
`config/beats/filebeat-ids01.yml` (keystore, module enable, `eve`
fileset `enabled: true`, `filebeat setup -e`, start service).
