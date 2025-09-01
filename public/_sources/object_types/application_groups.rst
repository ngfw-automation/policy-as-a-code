Application Groups
==================

Application groups allow you to group related applications for use in security policy rules. They can be based on specific applications or application filters.

File Location
~~~~~~~~~~~~~

Application groups are defined in the JSON file located at:

.. code-block:: text

   ngfw/objects/application groups/app_groups.json

This path is defined in the Settings module as ``APPLICATION_GROUPS_FILENAME``.

File Format
~~~~~~~~~~~

The ``app_groups.json`` file defines application groups that will be created on the Palo Alto Networks firewall. The file contains a JSON object with application group definitions.

Example JSON Structure
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

   {
     "application_groups": [
       {
         "name": "AG-collaboration-apps",
         "description": "Applications used for collaboration",
         "applications": [
           "ms-teams",
           "webex",
           "zoom"
         ]
       },
       {
         "name": "AG-web-browsing",
         "description": "Web browsing applications",
         "applications": [
           "web-browsing",
           "ssl"
         ]
       }
     ]
   }

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The application groups defined in this JSON file are processed by functions in the ``application_groups.py`` module. This module:

1. Parses the JSON file to extract application group definitions
2. Creates application group objects using the Palo Alto Networks SDK
3. Deploys the application groups to the PAN-OS device using multi-config API calls
