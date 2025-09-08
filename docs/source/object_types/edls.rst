External Dynamic Lists (EDLs)
==============================

External Dynamic Lists (EDLs) are lists of IP addresses, URLs, or domains that are hosted externally and periodically retrieved by the firewall. They are used in security policy rules to match specific IP addresses, URLs, or domains.

File Location
~~~~~~~~~~~~~

EDLs are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/external dynamic lists/edls.csv

This path is defined in the ``settings.py`` module as ``EDLS_FILENAME``.

File Format
~~~~~~~~~~~

The ``edls.csv`` file defines External Dynamic Lists that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single EDL configuration.

CSV Columns
^^^^^^^^^^^

+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Column Name      | Description                                                   | Required | Example                                   |
+==================+===============================================================+==========+===========================================+
| Name             | Name of the EDL                                               | Yes      | ``EDL-azure_atp``                         |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Type             | Type of EDL (ip, url, domain)                                 | Yes      | ``ip``                                    |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Repeat           | How often the EDL should be refreshed                         | Yes      | ``daily``, ``hourly``, ``five-minute``    |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Repeat At        | Specific time for refresh (if applicable)                     | No       | ``2`` (for 2:00 AM)                       |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Username         | Username for authentication (if required)                     | No       | ``admin``                                 |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Password         | Password for authentication (if required)                     | No       | ``password``                              |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Certificate      | Certificate profile for authentication (if required)          | No       | ``cert-profile-1``                        |
| Profile          |                                                               |          |                                           |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Source           | The URL source of the EDL                                     | Yes      | ``https://example.com/edls/azure_atp.txt``|
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+
| Description      | A description of the EDL                                      | No       | ``External EDL hosted by Example Inc.``   |
+------------------+---------------------------------------------------------------+----------+-------------------------------------------+

Usage Examples
~~~~~~~~~~~~~~

Basic EDL Configuration
^^^^^^^^^^^^^^^^^^^^^^^

To define a basic EDL, you need to specify at least the Name, Type, Repeat, and Source:

.. code-block:: text

   EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,,,,,https://example.com/edl.txt,External EDL hosted by Example Inc.

EDL Types
^^^^^^^^^

EDLs can be of different types:

1. **IP EDLs** - Used for lists of IP addresses:

   .. code-block:: text

      EDL-example,ip,daily,,,,,https://example.com/edls/ip-list.txt,External EDL with IP addresses

2. **URL EDLs** - Used for lists of URLs:

   .. code-block:: text

      EDL-URL-example,url,daily,,,,,https://example.com/edls/url-list.txt,External EDL with URLs

3. **Domain EDLs** - Used for lists of domains:

   .. code-block:: text

      EDL-DOM-example,domain,daily,,,,,https://example.com/edls/domain-list.txt,External EDL with domains

Refresh Schedules
^^^^^^^^^^^^^^^^^

EDLs can be refreshed at different intervals:

1. **Daily** - Refreshed once per day:

   .. code-block:: text

      EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,7,,,,https://example.com/edl.txt,Refreshed daily at 7 AM

2. **Hourly** - Refreshed once per hour:

   .. code-block:: text

      EDL-EXT-IP-DST-example,External EDL - Example,ip,hourly,,,,,https://example.com/edl.txt,Refreshed hourly

3. **Five-minute** - Refreshed every five minutes:

   .. code-block:: text

      EDL-EXT-IP-DST-example,External EDL - Example,ip,five-minute,,,,,https://example.com/edl.txt,Refreshed every five minutes

Environment-Specific EDLs
^^^^^^^^^^^^^^^^^^^^^^^^^

For EDLs that need to be environment-specific, use the ``<target_environment>`` placeholder in the Source URL:

.. code-block:: text

   EDL-IP-break_glass_dst,Internal EDL - IP DST - break-glass,ip,five-minute,,,,,https://edls.example.local/edl/<target_environment>/ip-dst-break-glass.txt,Internal EDL for break-glass scenarios

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The EDLs defined in this CSV file are processed by the ``create_edls`` function in the ``edls.py`` module. This function:

1. Parses the CSV file using the ``parse_metadata_from_csv`` function
2. Creates a table to display the EDLs being staged
3. Processes each EDL entry from the CSV file:
   - Handles formatting for the "Repeat At" field
   - Sets certificate profile, username, and password if provided
   - Handles environment-specific EDL source URLs by replacing ``<target_environment>`` placeholders
4. Creates EDL objects using the Palo Alto Networks SDK
5. Deploys the EDLs to the PAN-OS device using multi-config API calls
