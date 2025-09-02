URL Filtering Profiles
======================

URL filtering profiles define settings for URL filtering and categorization. They specify how the firewall should handle web traffic based on URL categories.

File Location
-------------

URL filtering profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/security profiles/url-filtering/

This path is defined in the Settings module as ``SECURITY_PROFILES_URL_FILTERING_FOLDER``.

File Format
-----------

URL filtering profiles can be defined in either JSON or YAML format. Each file represents a single URL filtering profile with settings for different URL categories and actions.

JSON Example
------------

.. code-block:: json

    {
        "entry": {
            "@name": "UFP-default",
            "credential-enforcement": {
                "mode": {
                    "disabled": {}
                }
            },
            "block": [
                "command-and-control",
                "malware",
                "phishing"
            ],
            "alert": [
                "adult",
                "gambling",
                "questionable"
            ],
            "allow": [
                "business-and-economy",
                "computer-and-internet-info",
                "content-delivery-networks",
                "education",
                "financial-services",
                "government",
                "health-and-medicine",
                "news",
                "search-engines",
                "web-based-email"
            ],
            "action": "block",
            "block-list": {
                "action": "block"
            },
            "allow-list": {
                "action": "allow"
            },
            "description": "URL filtering profile for regular traffic"
        }
    }

YAML Example
------------

.. code-block:: yaml

    entry:
      "@name": "UFP-default"
      credential-enforcement:
        mode:
          disabled: {}
      block:
        - "command-and-control"
        - "malware"
        - "phishing"
      alert:
        - "adult"
        - "gambling"
        - "questionable"
      allow:
        - "business-and-economy"
        - "computer-and-internet-info"
        - "content-delivery-networks"
        - "education"
        - "financial-services"
        - "government"
        - "health-and-medicine"
        - "news"
        - "search-engines"
        - "web-based-email"
      action: "block"
      block-list:
        action: "block"
      allow-list:
        action: "allow"
      description: "URL filtering profile for regular traffic"

Configuration Options
--------------------

URL filtering profiles support the following configuration options:

Category Settings
^^^^^^^^^^^^^^^^

URL filtering profiles can specify different actions for different URL categories:

- **block**: List of URL categories to block
- **alert**: List of URL categories to allow but generate an alert
- **allow**: List of URL categories to allow
- **action**: Default action for uncategorized URLs (block, alert, allow, override)

List Settings
^^^^^^^^^^^^

URL filtering profiles can include custom allow and block lists:

- **block-list**: Settings for the block list
  - **action**: Action to take for URLs in the block list (block, alert, allow, override)
- **allow-list**: Settings for the allow list
  - **action**: Action to take for URLs in the allow list (block, alert, allow, override)

Credential Enforcement
^^^^^^^^^^^^^^^^^^^^^

URL filtering profiles can enforce credential submission only to appropriate websites:

- **credential-enforcement**: Settings for credential enforcement
  - **mode**: Mode for credential enforcement (disabled, log, block)

Other Settings
^^^^^^^^^^^^^

- **description**: A description of the URL filtering profile

Implementation Details
---------------------

URL filtering profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for URL filtering profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the URL filtering profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
