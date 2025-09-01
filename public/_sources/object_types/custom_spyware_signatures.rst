Custom Spyware Signatures
=========================

Custom spyware signatures allow you to define your own spyware signatures for use in anti-spyware profiles.

File Location
~~~~~~~~~~~~~

Custom spyware signatures are defined in files located in:

.. code-block:: text

   ngfw/objects/custom objects/spyware/

This path is defined in the Settings module as ``CUSTOM_SPYWARE_SIGNATURES_FOLDER``.

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

Custom spyware signatures are processed by functions in various modules to create custom spyware signature objects using the Palo Alto Networks SDK. These functions:

1. Parse the configuration files for custom spyware signatures
2. Create custom spyware signature objects with the appropriate settings
3. Deploy the custom spyware signatures to the PAN-OS device using multi-config API calls

Custom spyware signatures can be used to:

- Define signatures for spyware that is not included in the predefined spyware database
- Create custom protection for specific types of malware or spyware
- Apply anti-spyware protection to custom applications
- Protect against zero-day spyware before official signatures are available
