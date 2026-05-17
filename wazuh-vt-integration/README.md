Wazuh → VirusTotal integration (file-hash lookups)

Overview

This folder contains a small integration that performs VirusTotal v3 lookups for file hashes detected by Wazuh.

Files

- `vt_lookup.py`: CLI script that queries VirusTotal for a file hash. Reads API key from `VT_API_KEY` or `/var/ossec/etc/vt_api.key`.
- `requirements.txt`: Python dependency (`requests`).
- `examples/local_rules.xml`: Example Wazuh rule to call the active-response command.
- `examples/ossec_commands_snippet.xml`: Snippet to add the `vt_lookup` command to `ossec.conf`.

Quick install (on Wazuh Manager)

1. Copy the script to the active-response directory:

```bash
sudo cp wazuh-vt-integration/vt_lookup.py /var/ossec/active-response/bin/
sudo chown root:ossec /var/ossec/active-response/bin/vt_lookup.py
sudo chmod 750 /var/ossec/active-response/bin/vt_lookup.py
```

2. Install dependency (inside manager):

```bash
sudo python3 -m pip install -r /path/to/wazuh-vt-integration/requirements.txt
```

3. Store your VirusTotal API key securely:

```bash
sudo sh -c 'echo "YOUR_API_KEY" > /var/ossec/etc/vt_api.key'
sudo chmod 600 /var/ossec/etc/vt_api.key
```

Alternatively set `VT_API_KEY` in the environment for the Wazuh Manager process.

4. Add the command snippet to `ossec.conf` (see `examples/ossec_commands_snippet.xml`) and add a rule to call the command (see `examples/local_rules.xml`).

5. Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

Testing

Run the script directly to test (no Wazuh involvement):

```bash
VT_API_KEY="<key>" python3 wazuh-vt-integration/vt_lookup.py <sha256> --short
```
