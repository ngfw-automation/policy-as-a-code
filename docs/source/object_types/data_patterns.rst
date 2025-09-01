Data Patterns
=============

Data patterns define patterns for data filtering profiles.

File Location
~~~~~~~~~~~~~

Data patterns are defined in files located in:

.. code-block:: text

   ngfw/objects/custom objects/data patterns/

This path is defined in the Settings module as ``DATA_PATTERNS_FOLDER``.

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

Data patterns are processed by functions in various modules to create data pattern objects using the Palo Alto Networks SDK. These functions:

1. Parse the configuration files for data patterns
2. Create data pattern objects with the appropriate settings
3. Deploy the data patterns to the PAN-OS device using multi-config API calls

Data patterns can be used to:

- Define patterns for sensitive data that should be monitored or blocked
- Create custom data filtering rules
- Apply data filtering to specific applications or traffic
- Protect against data leakage and exfiltration
