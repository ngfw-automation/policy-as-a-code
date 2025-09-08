Antivirus Profiles
==================

Antivirus profiles define settings for virus detection and prevention. They specify how the firewall should handle potentially malicious files across different protocols.

File Location
-------------

Antivirus profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/antivirus/

This path is defined in the ``settings.py`` module as ``SECURITY_PROFILES_ANTIVIRUS_FOLDER``.

File Format
-----------

Antivirus profiles can be defined in either JSON or YAML format. Each file represents a single antivirus profile with settings for different decoders (protocols) and machine learning-based antivirus (MLAV) engines.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "AVP-default",
            "decoder": {
                "entry": [
                    {
                        "@name": "smtp",
                        "action": "reset-both",
                        "wildfire-action": "reset-both",
                        "mlav-action": "default"
                    },
                    {
                        "@name": "http",
                        "action": "reset-both",
                        "wildfire-action": "reset-both",
                        "mlav-action": "default"
                    },
                    {
                        "@name": "ftp",
                        "action": "reset-both",
                        "wildfire-action": "reset-both",
                        "mlav-action": "default"
                    }
                ]
            },
            "mlav-engine-filebased-enabled": {
                "entry": [
                    {
                        "@name": "Windows Executables",
                        "mlav-policy-action": "enable(alert-only)"
                    },
                    {
                        "@name": "PowerShell Script 1",
                        "mlav-policy-action": "enable(alert-only)"
                    }
                ]
            },
            "description": "Antivirus profile for regular traffic",
            "packet-capture": "yes"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "AVP-default"
      decoder:
        entry:
          - "@name": "smtp"
            action: "reset-both"
            wildfire-action: "reset-both"
            mlav-action: "default"
          - "@name": "http"
            action: "reset-both"
            wildfire-action: "reset-both"
            mlav-action: "default"
          - "@name": "ftp"
            action: "reset-both"
            wildfire-action: "reset-both"
            mlav-action: "default"
      mlav-engine-filebased-enabled:
        entry:
          - "@name": "Windows Executables"
            mlav-policy-action: "enable(alert-only)"
          - "@name": "PowerShell Script 1"
            mlav-policy-action: "enable(alert-only)"
      description: "Antivirus profile for regular traffic"
      packet-capture: "yes"

Configuration Options
---------------------

Antivirus profiles support the following configuration options:

Decoder Settings
^^^^^^^^^^^^^^^^

Each decoder represents a protocol that the antivirus profile can scan:

- **smtp**: Email traffic using SMTP protocol
- **smb**: File sharing traffic using SMB protocol
- **pop3**: Email traffic using POP3 protocol
- **imap**: Email traffic using IMAP protocol
- **http2**: Web traffic using HTTP/2 protocol
- **http**: Web traffic using HTTP protocol
- **ftp**: File transfer traffic using FTP protocol

For each decoder, you can configure:

- **action**: Action to take when a virus is detected (alert, drop, reset-client, reset-server, reset-both, block-ip)
- **wildfire-action**: Action to take when WildFire detects a malicious file
- **mlav-action**: Action to take when machine learning-based antivirus detects a malicious file

MLAV Engine Settings
^^^^^^^^^^^^^^^^^^^^

The machine learning-based antivirus engine can be configured for different file types:

- **Windows Executables**: Windows executable files (.exe, .dll, etc.)
- **PowerShell Script 1**: PowerShell scripts
- **PowerShell Script 2**: Additional PowerShell script types
- **Executable Linked Format**: Linux executable files
- **MSOffice**: Microsoft Office documents
- **Shell**: Shell scripts

For each file type, you can configure:

- **mlav-policy-action**: Action to take (disable, enable(alert-only), enable(block))

Other Settings
^^^^^^^^^^^^^^

- **description**: A description of the antivirus profile
- **packet-capture**: Whether to capture packets when a virus is detected (yes, no)

Implementation Details
----------------------

Antivirus profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for antivirus profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the antivirus profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
