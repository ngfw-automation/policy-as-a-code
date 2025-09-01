.. _input_data_formats:

Input Data Formats
==================

This section explains the various input data formats used in the NGFW Policy as Code project. It covers all types of objects defined in the NGFW/OBJECTS folder.

.. toctree::
   :maxdepth: 1
   :caption: Object Types:

   object_types/service_objects
   object_types/edls
   object_types/address_objects
   object_types/custom_url_categories
   object_types/application_groups
   object_types/security_profiles
   object_types/tags
   object_types/decryption_profiles
   object_types/custom_applications
   object_types/custom_vulnerability_signatures
   object_types/custom_spyware_signatures
   object_types/data_patterns

Overview
--------

The NGFW Policy as Code project uses various input data formats to define objects that will be created on the Palo Alto Networks firewall. These objects are used to build security policies that enforce your organization's security requirements.

Each object type has its own specific format and requirements, which are detailed in the respective sections. Most object types are defined in CSV files, while some use JSON or other formats.

Common Patterns
----------------

Many of the object types follow common patterns in their implementation:

1. **File Parsing**: Most object types are defined in CSV files that are parsed using the ``parse_metadata_from_csv`` function.
2. **Object Creation**: The parsed data is used to create objects using the Palo Alto Networks SDK.
3. **Deployment**: The objects are deployed to the PAN-OS device using multi-config API calls.

For detailed information about each object type, please refer to the specific documentation pages linked above.
