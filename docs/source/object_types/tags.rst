Tags
====

Tags are used to categorize and organize objects in the firewall configuration.
They can be applied to various object types such as address objects, service objects,
and security rules.

File Location
~~~~~~~~~~~~~

Tags are defined directly in code in two modules located in the ``ngfw/objects/tags`` folder:

- ``ngfw/objects/tags/tags.py``
- ``ngfw/objects/tags/group_tags.py``

This segregation in two files is purely for readability purposes and easyness of administration.
The **tags** and **group tags** are identical objects from PAN-OS perspective.