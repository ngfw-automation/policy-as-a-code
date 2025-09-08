Application Groups
==================

Application groups allow you to group related applications for use in security policy rules. They can be based on specific applications or application filters.

File Location
~~~~~~~~~~~~~

Application groups are defined in the JSON file located at:

.. code-block:: text

   ngfw/objects/application groups/app_groups.json

This path is defined in the ``settings.py`` module as ``APPLICATION_GROUPS_FILENAME``.

File Format
~~~~~~~~~~~

The ``app_groups.json`` file defines application groups that will be created on the Palo Alto Networks firewall. The file contains a JSON object with application group definitions.

Example JSON Structure
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
        "name": "APG-web-browsing-risky",
        "value": [
          "web-browsing",
          "ssl",
          "google-base",
          "google-app-engine",
          "soap"
        ]
    }

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The application groups defined in this JSON file are processed by functions
in the ``lib/application_groups.py`` module.