.. _usage:

How to Use
==========

This section provides high-level instructions on how to use the project to create, customize, and deploy a firewall
policy customized for your environment.

Basic Workflow
--------------

1. **Define Requirements**: Review the policy requirements and update them if necessary (``requirements/categories_app.csv`` and ``requirements/categories_url.csv``)
2. **Define Deployment Targets**: Specify the target(s) to deploy the policy to (``requirements/policy_targets.json``)
3. **Customize Branding**: Customize response pages (``ngfw/device/response_pages``)
4. **Customize Policies**: Modify/add/delete static policy rules as needed (``ngfw/policies``)
5. **Ensure All Objects Are Defined**: All policy objects referenced in the policy rules must be defined (``ngfw/objects``)
6. **Update Zone Names**: Update the constants ``ZONE_INSIDE`` and ``ZONE_OUTSIDE`` in the ``settings.py`` module to match those configured on your target firewall(s)
7. **Ensure External Dependencies Are Met**: User-ID subsystem, NAT, EDL hosting, Service Desk workflows
8. **Create Backup**: Backup the entire running configuration of the target device
9. **Run the Script**: Execute the ``main.py`` script to generate and deploy the policy to a target (follow the interactive prompts)
10. **Review, Commit and Test**: Review the created policy, commit it to the running configuration and test

.. warning::
   Always deploy to a non-prod/lab device first.

.. tip::
   Refer to the companion book for testing and production deployment methodology.

Execution
---------

Command-line options are not implemented yet. Use the interactive mode by running the ``main.py`` script without any parameters.

.. code-block:: bash

   python main.py

Configuration Files
-------------------

The project uses several configuration files to define policy requirements:

Policy Targets
~~~~~~~~~~~~~~

The ``requirements/policy_targets.json`` file defines the target devices for policy deployment:

.. code-block:: json

    {
        "LAB Panorama": {
            "target_environment":         "lab",
            "panos_address":              "lab-panorama.example.com",
            "deployment_type":            "panorama",
            "firewall_vsys":              "",
            "panorama_device_group":      "nextgen-policy",
            "panorama_template":          "nextgen-policy-template"
        },
        "PROD Panorama": {
            "target_environment":         "prod",
            "panos_address":              "panorama.example.com",
            "deployment_type":            "panorama",
            "firewall_vsys":              "",
            "panorama_device_group":      "nextgen-policy",
            "panorama_template":          "nextgen-policy-template"
        },
        "LAB Firewall": {
            "target_environment":         "lab",
            "panos_address":              "192.168.1.1",
            "deployment_type":            "firewall",
            "firewall_vsys":              "vsys1",
            "panorama_device_group":      "",
            "panorama_template":          ""
        },
        "PROD Firewall": {
            "target_environment":         "prod",
            "panos_address":              "10.0.0.1",
            "deployment_type":            "firewall",
            "firewall_vsys":              "vsys1",
            "panorama_device_group":      "",
            "panorama_template":          ""
        },
    }

URL Categories
~~~~~~~~~~~~~~

The ``requirements/categories_url.csv`` file defines how the policy will handle standard URL categories:

.. code-block:: text

    Category,Abbreviation,Action,Approver,UserID,Description
    auctions,auctions,do not manage,,known-user,"Sites that promote the sale of goods between individuals."
    business-and-economy,business-economy,do not manage,,known-user,"Marketing, management, economics, and sites relating to entrepreneurship or running a business. Includes advertising and marketing firms. Should not include corporate websites as they should be categorized with their technology. Also shipping sites, such as fedex.com and ups.com."
    command-and-control,command-control,deny,,,"Command-and-control URLs and domains used by malware and/or compromised systems to surreptitiously communicate with an attacker's remote server to receive malicious commands or exfiltrate data"
    ...

This CSV file is equivalent to the table as follows:

.. list-table:: Sample URL Categories
   :widths: 20 15 15 10 10 30
   :header-rows: 1

   * - Category
     - Abbreviation
     - Action
     - Approver
     - UserID
     - Description
   * - auctions
     - auctions
     - do not manage
     - 
     - known-user
     - Sites that promote the sale of goods between individuals.
   * - business-and-economy
     - business-economy
     - do not manage
     - 
     - known-user
     - Marketing, management, economics, and sites relating to entrepreneurship or running a business.
   * - command-and-control
     - command-control
     - deny
     - 
     - 
     - Command-and-control URLs and domains used by malware and/or compromised systems.
   * - gambling
     - gambling
     - manage
     - human capital
     - UG-gambling
     - Lottery or gambling websites that facilitate the exchange of real and/or virtual money.

.. warning::
   Do not rename or delete any columns. Feel free to add custom columns (with comments, for example) - they will be ignored by the deployment script.

.. tip::
   For easier editing and management of this data, consider using a spreadsheet editor such as Microsoft Excel, Google Sheets, or LibreOffice Calc. These tools provide better visualization and filtering capabilities for managing large datasets.

Application Categories
~~~~~~~~~~~~~~~~~~~~~~

The ``requirements/categories_app.csv`` file defines how the policy will handle standard App-ID (sub)categories:

.. code-block:: text

   SubCategory,Action,Approver,UserID,Category,Tags,Risk,ExtraApps,ExcludedApps,Description
   encrypted-tunnel,deny,,,,,,,ssl,"VPN services, software, and protocols, as well as encrypted traffic that can tunnel other apps"
   erp-crm,do not manage,,known-user,,[Web App],"1,2,3,4",,,SaaS and on-premises enterprise resource planning (ERP) and customer relationship management (CRM) systems and software
   file-sharing,manage,compliance,UG-file-sharing,"general-internet, saas",[Web App],"1,2,3,4",google-drive-web,,"File storage and sharing applications, protocols, and cloud or SaaS services and their functions"
   ...


This CSV file is equivalent to the table as follows:

.. list-table:: Sample Application Categories
   :widths: 15 12 12 10 15 12 8 12 12 15
   :header-rows: 1

   * - SubCategory
     - Action
     - Approver
     - UserID
     - Category
     - Tags
     - Risk
     - ExtraApps
     - ExcludedApps
     - Description
   * - encrypted-tunnel
     - deny
     - 
     - 
     - 
     - 
     - 
     - 
     - ssl
     - VPN services, software, and protocols, as well as encrypted traffic that can tunnel other apps
   * - erp-crm
     - do not manage
     - 
     - known-user
     - 
     - [Web App]
     - 1,2,3,4
     - 
     - 
     - SaaS and on-premises enterprise resource planning (ERP) and customer relationship management (CRM) systems
   * - file-sharing
     - manage
     - compliance
     - UG-file-sharing
     - general-internet, saas
     - [Web App]
     - 1,2,3,4
     - google-drive-web
     - 
     - File storage and sharing applications, protocols, and cloud or SaaS services and their functions
   * - email
     - manage
     - compliance
     - UG-email
     - saas, collaboration
     - [Web App]
     - 1,2,3,4
     - office365-consumer-access
     - 
     - Online and on-premises email software and SaaS services, as well as email-related protocols

.. note::
   For easier editing and management of this data, consider using a spreadsheet editor such as Microsoft Excel, Google Sheets, or LibreOffice Calc. These tools provide better visualization and filtering capabilities for managing large datasets with multiple columns.

Usage Examples
--------------

Example 1: Basic Policy Deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To deploy policies to a target device:

1. Update the policy requirements as needed
2. Run the script:

   .. code-block:: bash

       python main.py

3. Select the target device from the menu
4. Wait for the deployment to complete
5. Commit the changes on the target device

Example 2: Customizing Address Objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To add or modify address objects:

1. Edit the appropriate file in `ngfw/objects/addresses/`:

   .. code-block:: python

       # Example: Adding a new address object
       address_objects = {
           "internal-server": {
               "ip_netmask": "192.168.1.100/32",
               "description": "Internal server",
               "tags": ["internal", "server"]
           },
           # Add more address objects as needed
       }

2. Run the script to deploy the changes

Example 3: Customizing Security Policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To add or modify security policies:

1. Edit the appropriate file in `ngfw/policies/security/`:

   .. code-block:: python

       # Example: Adding a new security rule
       security_rules = {
           "allow-internal-servers": {
               "action": "allow",
               "source_zones": ["trust"],
               "source_addresses": ["internal-network"],
               "destination_zones": ["untrust"],
               "destination_addresses": ["any"],
               "applications": ["web-browsing", "ssl"],
               "services": ["application-default"],
               "profile_group": "default"
           },
           # Add more security rules as needed
       }

2. Run the script to deploy the changes

Troubleshooting
---------------

Common Issues and Solutions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Connection Errors**:

   * Ensure the target device is reachable from your network
   * Verify the address in the policy_targets.json file
   * Check firewall rules that might be blocking the connection

2. **Authentication Errors**:

   * Ensure you have the correct credentials for the target device
   * Check if the API access is enabled on the target device

3. **Deployment Errors**:

   * Check the error messages for specific issues
   * Verify that the device group and template exist (for Panorama)
   * Ensure the VSYS exists (for standalone firewalls)

4. **Policy Generation Errors**:

   * Verify the syntax of your configuration files
   * Check for duplicate object names or rule names
   * Ensure all referenced objects exist

Logging and Debugging
~~~~~~~~~~~~~~~~~~~~~

To enable detailed logging for troubleshooting:

1. Run the script with the `--verbose` option:

   .. code-block:: bash

       python main.py --verbose

2. Check the log file in the `logs/` directory for detailed information

Getting Help
~~~~~~~~~~~~

If you encounter issues that you cannot resolve:

1. Check the project's GitHub issues page for known problems and solutions
2. Create a new issue on GitHub with detailed information about your problem
3. Consult the book "Palo Alto Networks from Policy to Code" for additional guidance
