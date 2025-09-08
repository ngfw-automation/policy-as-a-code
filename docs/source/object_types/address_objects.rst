Address Objects
===============

Address objects define network addresses, ranges, and domains that can be used in security policy rules. They can be grouped into address groups for easier management.

File Location
~~~~~~~~~~~~~

Address objects are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/addresses/address_objects.csv

This path is defined in the ``settings.py`` module as ``ADDRESS_OBJECTS_FILENAME``.

File Format
~~~~~~~~~~~

The ``address_objects.csv`` file defines address objects that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single address object or an address object that belongs to an address group.

Notes:
- Valid values for the ``Type`` column are exactly: ``IP Netmask``, ``IP Wildcard``, ``IP Range``, ``FQDN``, ``Static Group``. Rows with other values default to ``IP Netmask``.
- Rows with ``Type`` = ``Static Group`` do not create an address object; they declare that the value in ``Name`` is a member (object or group) of the ``Group Name`` address group.
- The ``Group Tags`` column is currently not used by the implementation.

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

Address objects and groups are staged by the ``stage_address_objects()`` function in ``lib/address_objects_staging.py``. In summary, it:

1) Parses input:

   - Reads the CSV at ``settings.ADDRESS_OBJECTS_FILENAME`` via ``lib.auxiliary_functions.parse_metadata_from_csv()``.
   - Accepts Type values: ``IP Netmask``, ``IP Wildcard``, ``IP Range``, ``FQDN``, and ``Static Group``. Any other value defaults to ``IP Netmask``.

2) Creates address objects:

   - Maps CSV types to PAN-OS SDK keywords: IP Netmask → ``ip-netmask`` (default), IP Wildcard → ``ip-wildcard``, IP Range → ``ip-range``, FQDN → ``fqdn``.
   - Tags (semicolon-separated) are split and trimmed; empty Tags become ``None``. Descriptions are trimmed; empty descriptions become ``None``.
   - Each non–Static Group row creates a ``panos.objects.AddressObject`` with name, type, value, description, and tag set accordingly.

3) Creates static address groups from CSV:

   - For any row with a non-empty ``Group Name`` that starts with ``AG-``, the row’s ``Name`` is included in that static ``AddressGroup``.
   - ``Static Group`` rows allow building group-of-groups (nested groups): a row with Type ``Static Group`` adds the ``Name`` (which must be an existing ``AddressObject`` or ``AddressGroup``) into the ``Group Name`` group.
   - Group descriptions are taken from the first non-empty ``Group Description`` seen for that group. CSV Group Tags are not used by the current code.

4) Adds additional sources (beyond the CSV):

   - GitHub Git-over-SSH addresses: fetched live from ``https://api.github.com/meta``; each IPv4 entry becomes an AddressObject. A static group ``AG-github_git`` is created with these objects.
   - Optional AD Domain Controllers (if ``settings.UPDATE_AD_DC_LIST`` is ``True``): SRV and A records are resolved from ``settings.AD_DOMAIN_NAME_DNS``; each DC IP becomes an AddressObject tagged with the ``ad-dc`` tag from ``ngfw.objects.tags.tags``.

5) Creates dynamic groups:

   - Dynamic Address Groups: ``DAG-domain-controllers``, ``DAG-compromised_hosts``, ``DAG-tls_d_auto_exceptions`` are created using tag-based ``dynamic_value`` filters.
   - Dynamic User Group: ``DUG-compromised_users`` is created (side effect of this staging function and may be relevant to policy logic).

6) Computes delta and deploys via multi-config API:

   - The synchronization function ``handle_address_objects_and_groups()`` computes differences between current and staged objects/groups using ``lib.auxiliary_functions.find_address_objects_delta()`` and ``find_address_groups_delta()``.
   - Deployment uses batched multi-config XML calls via ``execute_multi_config_api_call()``: redundant/modified objects/groups are deleted, and new/updated ones are created.

.. note::
    - Group names must start with ``AG-`` to be created; non-conforming names are ignored and reported.
    - Unknown Type values in the CSV are treated as ``IP Netmask``.
    - CSV ``Group Tags`` are currently ignored by code and have no effect.
