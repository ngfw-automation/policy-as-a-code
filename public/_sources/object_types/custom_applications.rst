Custom Applications
===================

Custom applications allow you to define your own applications for use in security policy rules.

File Location
~~~~~~~~~~~~~

Custom applications are defined in files located in:

.. code-block:: text

   ngfw/objects/applications/

This path is defined in the Settings module as ``CUSTOM_APPLICATION_SIGNATURES_FOLDER``.

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

Custom applications are processed by functions in various modules to create custom application objects using the Palo Alto Networks SDK. These functions:

1. Parse the configuration files for custom applications
2. Create custom application objects with the appropriate settings
3. Deploy the custom applications to the PAN-OS device using multi-config API calls

Custom applications can be used to:

- Define applications that are not included in the predefined application database
- Create application signatures based on specific traffic patterns
- Apply security policies to custom applications
- Monitor and control traffic for custom applications
