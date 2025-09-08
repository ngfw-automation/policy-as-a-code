Security Profiles
=================

Security profiles define security settings for various security features such as antivirus, anti-spyware, vulnerability protection, URL filtering, file blocking, data filtering, and WildFire analysis.

Overview
--------

Security profiles are a critical component of the Palo Alto Networks firewall's security capabilities. They allow you to define how the firewall should handle different types of traffic and content based on various security considerations.

File Locations
--------------

Security profiles are defined in JSON or YAML files located in various subdirectories under:

.. code-block:: text

   ngfw/objects/security profiles/

The paths to these subdirectories are defined in the ``settings.py`` module:

- ``SECURITY_PROFILES_DATA_FILTERING_FOLDER``
- ``SECURITY_PROFILES_VULNERABILITY_FOLDER``
- ``SECURITY_PROFILES_ANTISPYWARE_FOLDER``
- ``SECURITY_PROFILES_ANTIVIRUS_FOLDER``
- ``SECURITY_PROFILES_WILDFIRE_FOLDER``
- ``SECURITY_PROFILES_FILE_BLOCKING_FOLDER``
- ``SECURITY_PROFILES_URL_FILTERING_FOLDER``

Security Profile Types
----------------------

The NGFW Policy as Code project supports the following security profile types:

.. toctree::
   :maxdepth: 1

   security_profiles/antivirus_profiles
   security_profiles/anti_spyware_profiles
   security_profiles/vulnerability_protection_profiles
   security_profiles/url_filtering_profiles
   security_profiles/file_blocking_profiles
   security_profiles/data_filtering_profiles
   security_profiles/wildfire_analysis_profiles

Implementation Details
-----------------------

Security profiles are processed by functions in various modules to create security profile objects using the Palo Alto Networks SDK. These functions:

1. Parse the JSON or YAML files for each security profile type
2. Create security profile objects with the appropriate settings
3. Deploy the security profiles to the PAN-OS device using multi-config API calls
