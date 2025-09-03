WildFire Analysis Profiles
==========================

WildFire analysis profiles define settings for WildFire cloud-based threat analysis. They specify how the firewall should handle files that need to be analyzed by the WildFire service.

File Location
-------------

WildFire analysis profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/wildfire/

This path is defined in the Settings module as ``SECURITY_PROFILES_WILDFIRE_FOLDER``.

File Format
-----------

WildFire analysis profiles can be defined in either JSON or YAML format. Each file represents a single WildFire analysis profile with settings for different file types and applications.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "WFP-default",
            "rules": {
                "entry": [
                    {
                        "@name": "Forward-EXE-Files",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "pe"
                        ],
                        "direction": "both",
                        "analysis": "public-cloud"
                    },
                    {
                        "@name": "Forward-PDF-Files",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "pdf"
                        ],
                        "direction": "both",
                        "analysis": "public-cloud"
                    },
                    {
                        "@name": "Forward-Office-Files",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "ms-office"
                        ],
                        "direction": "both",
                        "analysis": "public-cloud"
                    }
                ]
            },
            "description": "WildFire analysis profile for regular traffic"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "WFP-default"
      rules:
        entry:
          - "@name": "Forward-EXE-Files"
            application:
              - "any"
            file-type:
              - "pe"
            direction: "both"
            analysis: "public-cloud"
          - "@name": "Forward-PDF-Files"
            application:
              - "any"
            file-type:
              - "pdf"
            direction: "both"
            analysis: "public-cloud"
          - "@name": "Forward-Office-Files"
            application:
              - "any"
            file-type:
              - "ms-office"
            direction: "both"
            analysis: "public-cloud"
      description: "WildFire analysis profile for regular traffic"

Configuration Options
---------------------

WildFire analysis profiles support the following configuration options:

Rules
^^^^^

Rules define how the firewall should handle different file types for WildFire analysis:

- **application**: Applications to which the rule applies (any, specific application names)
- **file-type**: File types to which the rule applies (pe, pdf, ms-office, etc.)
- **direction**: Direction of file transfer to which the rule applies (upload, download, both)
- **analysis**: Type of analysis to perform (public-cloud, private-cloud, hybrid-cloud)

Other Settings
^^^^^^^^^^^^^^

- **description**: A description of the WildFire analysis profile

Implementation Details
----------------------

WildFire analysis profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for WildFire analysis profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the WildFire analysis profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
