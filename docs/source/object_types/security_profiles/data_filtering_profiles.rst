Data Filtering Profiles
=======================

Data filtering profiles define settings for data leak prevention. They specify how the firewall should handle sensitive data patterns in network traffic.

File Location
-------------

Data filtering profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/data filtering/

This path is defined in the Settings module as ``SECURITY_PROFILES_DATA_FILTERING_FOLDER``.

File Format
-----------

Data filtering profiles can be defined in either JSON or YAML format. Each file represents a single data filtering profile with settings for different data patterns and applications.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "DFP-default",
            "rules": {
                "entry": [
                    {
                        "@name": "Block-Credit-Card-Numbers",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "any"
                        ],
                        "direction": "both",
                        "alert-threshold": 1,
                        "block-threshold": 1,
                        "data-object": [
                            "credit-card-numbers"
                        ],
                        "log-severity": "high",
                        "action": "block"
                    },
                    {
                        "@name": "Alert-SSN",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "any"
                        ],
                        "direction": "both",
                        "alert-threshold": 1,
                        "block-threshold": 0,
                        "data-object": [
                            "social-security-numbers"
                        ],
                        "log-severity": "medium",
                        "action": "alert"
                    }
                ]
            },
            "description": "Data filtering profile for regular traffic"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "DFP-default"
      rules:
        entry:
          - "@name": "Block-Credit-Card-Numbers"
            application:
              - "any"
            file-type:
              - "any"
            direction: "both"
            alert-threshold: 1
            block-threshold: 1
            data-object:
              - "credit-card-numbers"
            log-severity: "high"
            action: "block"
          - "@name": "Alert-SSN"
            application:
              - "any"
            file-type:
              - "any"
            direction: "both"
            alert-threshold: 1
            block-threshold: 0
            data-object:
              - "social-security-numbers"
            log-severity: "medium"
            action: "alert"
      description: "Data filtering profile for regular traffic"

Configuration Options
--------------------

Data filtering profiles support the following configuration options:

Rules
^^^^^

Rules define how the firewall should handle different data patterns:

- **application**: Applications to which the rule applies (any, specific application names)
- **file-type**: File types to which the rule applies (any, specific file types)
- **direction**: Direction of data transfer to which the rule applies (upload, download, both)
- **alert-threshold**: Number of matches required to generate an alert
- **block-threshold**: Number of matches required to block the traffic
- **data-object**: Data patterns to match (credit-card-numbers, social-security-numbers, custom patterns)
- **log-severity**: Severity level for log entries (high, medium, low, informational)
- **action**: Action to take when a matching pattern is detected (alert, block)

Other Settings
^^^^^^^^^^^^^

- **description**: A description of the data filtering profile

Implementation Details
---------------------

Data filtering profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for data filtering profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the data filtering profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
