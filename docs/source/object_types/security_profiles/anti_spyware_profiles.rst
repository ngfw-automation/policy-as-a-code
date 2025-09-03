Anti-spyware Profiles
=====================

Anti-spyware profiles define settings for spyware detection and prevention. They specify how the firewall should handle potentially malicious spyware across different protocols.

File Location
-------------

Anti-spyware profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/anti-spyware/

This path is defined in the Settings module as ``SECURITY_PROFILES_ANTISPYWARE_FOLDER``.

File Format
-----------

Anti-spyware profiles can be defined in either JSON or YAML format. Each file represents a single anti-spyware profile with settings for different threat severities and actions.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "ASP-default",
            "rules": {
                "entry": [
                    {
                        "@name": "Block-Critical-High-Medium",
                        "threat-name": "any",
                        "category": "any",
                        "severity": [
                            "critical",
                            "high",
                            "medium"
                        ],
                        "action": {
                            "reset-both": "yes"
                        },
                        "packet-capture": "disable"
                    },
                    {
                        "@name": "Default-Low-Info",
                        "threat-name": "any",
                        "category": "any",
                        "severity": [
                            "low",
                            "informational"
                        ],
                        "action": {
                            "default": "yes"
                        },
                        "packet-capture": "disable"
                    }
                ]
            },
            "botnet-domains": {
                "lists": {
                    "entry": [
                        {
                            "@name": "default-paloalto-dns",
                            "action": {
                                "reset-both": "yes"
                            },
                            "packet-capture": "disable"
                        }
                    ]
                },
                "sinkhole": {
                    "ipv4-address": "sinkhole.paloaltonetworks.com",
                    "ipv6-address": "2600:5200::1"
                }
            },
            "description": "Anti-spyware profile for regular traffic"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "ASP-default"
      rules:
        entry:
          - "@name": "Block-Critical-High-Medium"
            threat-name: "any"
            category: "any"
            severity:
              - "critical"
              - "high"
              - "medium"
            action:
              reset-both: "yes"
            packet-capture: "disable"
          - "@name": "Default-Low-Info"
            threat-name: "any"
            category: "any"
            severity:
              - "low"
              - "informational"
            action:
              default: "yes"
            packet-capture: "disable"
      botnet-domains:
        lists:
          entry:
            - "@name": "default-paloalto-dns"
              action:
                reset-both: "yes"
              packet-capture: "disable"
        sinkhole:
          ipv4-address: "sinkhole.paloaltonetworks.com"
          ipv6-address: "2600:5200::1"
      description: "Anti-spyware profile for regular traffic"

Configuration Options
---------------------

Anti-spyware profiles support the following configuration options:

Rules
^^^^^

Rules define how the firewall should handle different types of spyware threats:

- **threat-name**: Name of the threat to match (any, specific threat name)
- **category**: Category of the threat to match (any, specific category)
- **severity**: Severity levels to match (critical, high, medium, low, informational)
- **action**: Action to take when a threat is detected (default, allow, alert, drop, reset-client, reset-server, reset-both, block-ip)
- **packet-capture**: Whether to capture packets when a threat is detected (disable, single-packet, extended-capture)

Botnet Domains
^^^^^^^^^^^^^^

The botnet-domains section configures how the firewall handles botnet command and control traffic:

- **lists**: Lists of botnet domains to block
  - **action**: Action to take when botnet traffic is detected
  - **packet-capture**: Whether to capture packets when botnet traffic is detected
- **sinkhole**: Configuration for sinkhole addresses
  - **ipv4-address**: IPv4 address for the sinkhole
  - **ipv6-address**: IPv6 address for the sinkhole

Other Settings
^^^^^^^^^^^^^^

- **description**: A description of the anti-spyware profile

Implementation Details
----------------------

Anti-spyware profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for anti-spyware profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the anti-spyware profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
