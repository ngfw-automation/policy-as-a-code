Tags
====

Tags are used to categorize and organize objects in the firewall configuration. They can be applied to various object types such as address objects, service objects, and security rules.

File Location
~~~~~~~~~~~~~

Tags are defined in files located in:

.. code-block:: text

   ngfw/objects/tags/

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

Tags are processed by functions in the ``tags.py`` module. This module:

1. Creates tag objects using the Palo Alto Networks SDK
2. Applies tags to various objects in the firewall configuration
3. Deploys the tags to the PAN-OS device using multi-config API calls

Tags can be used to:

- Group related objects together
- Apply consistent policies to objects with the same tag
- Filter and search for objects in the firewall configuration
- Automate policy management based on tags
