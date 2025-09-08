File Blocking Profiles
======================

File blocking profiles define settings for blocking specific file types. They specify how the firewall should handle different file types across various applications.

File Location
-------------

File blocking profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/file blocking/

This path is defined in the ``settings.py`` module as ``SECURITY_PROFILES_FILE_BLOCKING_FOLDER``.

File Format
-----------

File blocking profiles can be defined in either JSON or YAML format. Each file represents a single file blocking profile with settings for different file types and applications.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "FBP-default",
            "rules": {
                "entry": [
                    {
                        "@name": "Block-Executables",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "exe",
                            "dll",
                            "bat",
                            "scr",
                            "pif"
                        ],
                        "direction": "both",
                        "action": "block"
                    },
                    {
                        "@name": "Alert-Office-Documents",
                        "application": [
                            "any"
                        ],
                        "file-type": [
                            "doc",
                            "docx",
                            "xls",
                            "xlsx",
                            "ppt",
                            "pptx"
                        ],
                        "direction": "both",
                        "action": "alert"
                    }
                ]
            },
            "description": "File blocking profile for regular traffic"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "FBP-default"
      rules:
        entry:
          - "@name": "Block-Executables"
            application:
              - "any"
            file-type:
              - "exe"
              - "dll"
              - "bat"
              - "scr"
              - "pif"
            direction: "both"
            action: "block"
          - "@name": "Alert-Office-Documents"
            application:
              - "any"
            file-type:
              - "doc"
              - "docx"
              - "xls"
              - "xlsx"
              - "ppt"
              - "pptx"
            direction: "both"
            action: "alert"
      description: "File blocking profile for regular traffic"

Configuration Options
---------------------

File blocking profiles support the following configuration options:

Rules
^^^^^

Rules define how the firewall should handle different file types:

- **application**: Applications to which the rule applies (any, specific application names)
- **file-type**: File types to which the rule applies (exe, dll, bat, doc, docx, etc.)
- **direction**: Direction of file transfer to which the rule applies (upload, download, both)
- **action**: Action to take when a matching file is detected (alert, block, continue)

Other Settings
^^^^^^^^^^^^^^

- **description**: A description of the file blocking profile

Implementation Details
----------------------

File blocking profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for file blocking profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the file blocking profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
