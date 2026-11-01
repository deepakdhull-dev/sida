# RUNBOOK — Security Incident Detection and Analysis
Orion Freight Ltd. lab. Network: 192.168.56.0/24 (host-only), host at .1.

## 0. Host prerequisites
- VirtualBox with Extension Pack installed.
- Create a Host-Only Network: `vboxmanage hostonlyif create` → confirm it is 192.168.56.1/24, DHCP server disabled.
- 16 GB host RAM recommended (12 GB is the spec minimum; see constraint note in project decisions).

## 1. Create VMs

| Host | OS | RAM | vCPU | Disk | Adapters |
|---|---|---|---|---|---|
| SIEM-01 | Ubuntu Server (latest LTS) | 4096 MB | 2 | 30 GB | NAT + Host-only (.10) |
| IDS-01 | Ubuntu Server (latest LTS) | 2048 MB | 1 | 20 GB | NAT + Host-only (.11), **Promiscuous Mode: Allow All** on the host-only adapter |
| UBU-APP01 | Ubuntu Server (latest LTS) | 1536 MB | 1 | 20 GB | NAT + Host-only (.20) |
| WIN-FS01 | Windows Server evaluation ISO | 3072 MB | 2 | 50 GB | NAT + Host-only (.30) |
| KALI-ATK01 | Kali Linux | 1536 MB | 2 | 30 GB | NAT + Host-only (.50) |

WKS-014 is a logical asset only — no VM is created for it. Its logs are injected (see `simulation/phishing_inject.py`).

Power off KALI-ATK01 between use to keep total RAM under the 16 GB host budget.

## 2. OS install
Install each OS with default settings. Enable SSH server during UBU-APP01 and SIEM-01 and IDS-01 install. On every Linux VM: `sudo timedatectl set-timezone UTC`.

On UBU-APP01, create the brute-force target account and make sure SSH accepts passwords and auth.log exists:
```
sudo adduser svcapp          # password = line 14 of simulation/wordlist.txt (Harvest#26)
sudo sshd -T | grep -Ei 'passwordauthentication|persourcepenalties'
```
- If `passwordauthentication no`: set `PasswordAuthentication yes` in `/etc/ssh/sshd_config.d/99-lab.conf`.
- If a `persourcepenalties` line is printed (OpenSSH 9.8+): add `PerSourcePenalties no` to the same file. Otherwise sshd blocks Hydra after a few failures and attempt 14 is never reached. Disclose this in the report as a lab simplification.
- `sudo systemctl restart ssh`
- `ls /var/log/auth.log`. If it is missing, run `sudo apt install -y rsyslog`. The Filebeat system module reads this file.

## 3. Apply network config
Copy the matching file from `config/network/` to each Linux VM's `/etc/netplan/`, adjust the host-only interface name to match `ip a` output, then:
```
sudo netplan apply
```
On WIN-FS01, set the host-only adapter's IPv4 address to 192.168.56.30/24 manually via Network Settings.

On KALI-ATK01:
```
sudo nmcli con add type ethernet ifname eth1 con-name lab ipv4.method manual ipv4.addresses 192.168.56.50/24
sudo nmcli con up lab
```
Verify with `ping` between all hosts.

**Screenshot:** VM network settings for each host (Deliverable 1 evidence).

## 4. Time sync
- SIEM-01: install chrony, apply `config/time-sync/chrony-siem01.conf`, restart chrony.
- IDS-01 and UBU-APP01: install chrony, apply `config/time-sync/chrony-client.conf`, restart chrony.
- WIN-FS01: run `config/time-sync/w32time-winfs01.ps1` as Administrator.
- Verify all VMs show UTC and `chronyc tracking` / `w32tm /query /status` report SIEM-01 as the source.

**Screenshot:** `chronyc sources` on two Linux hosts, `w32tm /query /status` on WIN-FS01.

## 5. Deploy ELK on SIEM-01
```
sudo apt install -y docker.io docker-compose-v2
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system

cd config/elk
cp .env.example .env    # set both passwords; KIBANA_ENCRYPTION_KEY = output of: openssl rand -hex 32
sudo docker compose up -d elasticsearch
sudo docker compose ps   # wait until elasticsearch shows (healthy)
./set-kibana-system-password.sh
sudo docker compose up -d kibana
```
Confirm `http://192.168.56.10:9200` and `http://192.168.56.10:5601` respond, and log in to Kibana as `elastic`.

**Screenshot:** `docker compose ps` showing both containers healthy.

## 6. Install Beats
Install the same version as `STACK_VERSION` (Elastic APT repo on Ubuntu, MSI/zip on Windows). For each host, replace the default config with the file below, then run the setup commands in that file's header comment. They cover the keystore entry for `ELASTIC_PASSWORD`, enabling the module filesets, `setup -e`, and starting the service.
- UBU-APP01: `config/beats/filebeat-ubu-app01.yml`
- IDS-01: `config/beats/filebeat-ids01.yml` (do this after step 8)
- WIN-FS01: `config/beats/winlogbeat-winfs01.yml` (do this after step 7)

## 7. Install Sysmon on WIN-FS01
Run `config/sysmon/install-sysmon.ps1` as Administrator. It installs Sysmon with `config/sysmon/sysmonconfig.xml`.

## 8. Install Suricata on IDS-01
Follow `config/suricata/suricata-setup.md`. Append `config/suricata/local.rules`. Confirm the host-only adapter is in Promiscuous Mode "Allow All" (VirtualBox adapter setting, not an OS setting).

## 9. Verify ingestion
Create the data views listed at the top of `dashboard/dashboard_build_spec.md`. In Kibana → Discover, confirm documents are arriving from:
- `filebeat-*` (UBU-APP01 auth/syslog)
- `filebeat-*` (IDS-01 Suricata eve.json)
- `winlogbeat-*` (WIN-FS01 Security, Sysmon, Defender channels)

**Screenshot:** Discover view per source (Deliverable 1 evidence — log ingestion).

## 10. Create detection rules
On a host with network access to Kibana and `curl`/`python3` (SIEM-01 or the VirtualBox host):
```
export ES_PASSWORD='<elastic password from .env>'
cd detection
./create_rules.sh
```
**Screenshot:** Kibana → Alerting → Rules list showing all four rules (Deliverable 1 evidence).

## 11. Build the dashboard
Follow `dashboard/dashboard_build_spec.md` to build the four-section dashboard manually in Kibana.

## 12. Run simulations, in this order
First, isolate the lab (decision D5). Power off each VM, or use Devices → Network, and disconnect the cable on Adapter 1 (NAT) for every VM. Only the host-only network remains.

1. **INC-001 Port scan**: on IDS-01, start the capture `sudo tcpdump -i enp0s8 -w portscan.pcap host 192.168.56.50`. From KALI-ATK01, run `simulation/portscan.sh`. Stop tcpdump with Ctrl+C and open `portscan.pcap` in Wireshark for the evidence screenshot.
2. **INC-002 Brute force**: from KALI-ATK01, run `simulation/bruteforce.sh`.
3. **INC-003 Malware**: on KALI-ATK01, start `python3 simulation/beacon_listener.py`. On WIN-FS01 (as Administrator), run `simulation/malware_sim.ps1`.
4. **INC-004 Phishing**: from SIEM-01 (or any host that can reach Elasticsearch), run `ELASTIC_PASSWORD='<elastic password>' python3 simulation/phishing_inject.py`.

Leave 2–3 minutes between simulations so alerts and dashboard panels separate cleanly on the time axis.

**Screenshots per incident:**
- Triggered alert in Kibana (rule name, time, severity).
- Relevant raw log lines in Discover.
- `tcpdump`/Wireshark capture for INC-001 (packet-level evidence only, not ingested).
- Terminal output of the simulation script.

## 13. Capture final dashboard evidence
After all four simulations, screenshot each of the four dashboard sections (Deliverable 3).

## 14. Compile the report
Fill the incident entries in `report/` using the evidence collected above, once ready. See `report/README.md`.
