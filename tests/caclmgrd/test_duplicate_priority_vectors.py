# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
    caclmgrd test vector for control plane ACL rules that share a PRIORITY
"""

RULE_A_CMD = ['iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '192.0.2.0/24', '--dport', '22', '-j', 'ACCEPT']
RULE_B_CMD = ['iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '198.51.100.0/24', '--dport', '22', '-j', 'ACCEPT']
RULE_KEEP_CMD = ['iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '10.0.0.0/8', '--dport', '22', '-j', 'ACCEPT']


def _config_db(rules):
    return {
        "ACL_TABLE": {
            "SSH_ONLY": {
                "policy_desc": "SSH_ONLY",
                "services": ["SSH"],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
        },
        "ACL_RULE": rules,
        "DEVICE_METADATA": {
            "localhost": {
            }
        },
        "FEATURE": {},
    }


DUPLICATE_PRIORITY_TEST_VECTOR = [
    [
        "Two rules with the same PRIORITY: the last one read is applied and a warning names both",
        {
            "config_db": _config_db({
                "SSH_ONLY|RULE_KEEP": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10010", "SRC_IP": "10.0.0.0/8"},
                "SSH_ONLY|RULE_A": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10000", "SRC_IP": "192.0.2.0/24"},
                "SSH_ONLY|RULE_B": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10000", "SRC_IP": "198.51.100.0/24"},
            }),
            "present": [RULE_KEEP_CMD, RULE_B_CMD],
            "absent": [RULE_A_CMD],
            "warnings": [
                "CtrlPlane ACL table SSH_ONLY: rules RULE_A, RULE_B have the same PRIORITY 10000. "
                "Only one rule per PRIORITY is applied: rule RULE_B is applied and the others are ignored."
            ],
        }
    ],
    [
        "Different PRIORITY values: every rule is applied and nothing is reported",
        {
            "config_db": _config_db({
                "SSH_ONLY|RULE_KEEP": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10010", "SRC_IP": "10.0.0.0/8"},
                "SSH_ONLY|RULE_A": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10000", "SRC_IP": "192.0.2.0/24"},
                "SSH_ONLY|RULE_B": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10001", "SRC_IP": "198.51.100.0/24"},
            }),
            "present": [RULE_KEEP_CMD, RULE_A_CMD, RULE_B_CMD],
            "absent": [],
            "warnings": [],
        }
    ],
    [
        "Same PRIORITY and the second rule is IPv6 in an IPv4 table: neither rule is applied",
        {
            "config_db": _config_db({
                "SSH_ONLY|RULE_KEEP": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10010", "SRC_IP": "10.0.0.0/8"},
                "SSH_ONLY|RULE_A": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10000", "SRC_IP": "192.0.2.0/24"},
                "SSH_ONLY|RULE_V6": {"PACKET_ACTION": "ACCEPT", "PRIORITY": "10000", "SRC_IPV6": "2001:db8::/32"},
            }),
            "present": [RULE_KEEP_CMD],
            "absent": [RULE_A_CMD],
            "warnings": [
                "CtrlPlane ACL table SSH_ONLY: rules RULE_A, RULE_V6 have the same PRIORITY 10000. "
                "Only one rule per PRIORITY is applied: none of them is applied."
            ],
        }
    ],
]
