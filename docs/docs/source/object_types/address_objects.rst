Address Objects
===============

Address objects define network addresses, ranges, and domains that can be used in security policy rules. They can be grouped into address groups for easier management.

File Location
~~~~~~~~~~~~~

Address objects are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/addresses/address_objects.csv

This path is defined in the Settings module as ``ADDRESS_OBJECTS_FILENAME``.

File Format
~~~~~~~~~~~

The ``address_objects.csv`` file defines address objects that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single address object or an address object that belongs to an address group.

CSV Columns
^^^^^^^^^^^

+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Column Name      | Description                                                   | Required | Example                                  |
+==================+===============================================================+==========+==========================================+
| Name             | Name of the address object                                    | Yes      | ``N-rfc_1918-10.0.0.0_8``                |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Type             | Type of address object (IP Netmask, IP Wildcard, IP Range,    | Yes      | ``IP Netmask``                           |
|                  | FQDN, Static Group)                                           |          |                                          |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Address          | The actual address value                                      | Yes      | ``10.0.0.0/8``, ``time.apple.com``       |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Tags             | Semicolon-separated list of tags to apply to the address      | No       | ``internal;trusted``                     |
|                  | object                                                        |          |                                          |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Description      | Optional description for the address object                   | No       | ``RFC 1918 private address space``       |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Group Name       | Name of the address group this object belongs to              | No       | ``AG-internal_network``                  |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Group Tags       | Tags to apply to the address group                            | No       | ``internal;network``                     |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Group Description| Description for the address group                             | No       | ``Internal network address space``       |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+

Usage Examples
~~~~~~~~~~~~~~

Basic Address Object
^^^^^^^^^^^^^^^^^^^^

To define a basic IP Netmask address object:

.. code-block:: text

   N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,,,

Address Object Types
^^^^^^^^^^^^^^^^^^^^

Address objects can be of different types:

1. **IP Netmask** - Used for IP addresses with subnet masks:

   .. code-block:: text

      N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,,,

2. **IP Wildcard** - Used for IP addresses with wildcard masks:

   .. code-block:: text

      WC-example,IP Wildcard,10.0.0.0/0.0.0.255,,,,,

3. **IP Range** - Used for a range of IP addresses:

   .. code-block:: text

      R-dhcp-pool,IP Range,192.168.1.100-192.168.1.200,,,,,

4. **FQDN** - Used for fully qualified domain names:

   .. code-block:: text

      FQDN-time.apple.com,FQDN,time.apple.com,,,,,

Address Object in a Group
^^^^^^^^^^^^^^^^^^^^^^^^^

To add an address object to an address group:

.. code-block:: text

   N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,AG-internal_network,,This group represents the internal network of your organization

Multiple Address Objects in a Group
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can add multiple address objects to the same group:

.. code-block:: text

   N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,AG-internal_network,,This group represents the internal network of your organization
   N-rfc_1918-172.16.0.0_12,IP Netmask,172.16.0.0/12,,,AG-internal_network,,
   N-rfc_1918-192.168.0.0_16,IP Netmask,192.168.0.0/16,,,AG-internal_network,,

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The address objects defined in this CSV file are processed by the ``stage_address_objects`` function in the ``address_objects_staging.py`` module. This function:

1. Parses the CSV file using the ``parse_metadata_from_csv`` function
2. Converts human-readable types from the CSV file to exact API keywords
3. Processes tags and descriptions
4. Creates address objects using the Palo Alto Networks SDK
5. Creates static and dynamic address groups
6. Handles nested groups (groups of groups)
7. Deploys the address objects and groups to the PAN-OS device using multi-config API calls
