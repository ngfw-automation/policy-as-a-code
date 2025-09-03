Service Objects
===============

Service objects define network services based on protocol and port information. They are used in security policy rules to match specific protocols and ports.

File Location
~~~~~~~~~~~~~

Service objects are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/services/service_objects.csv

This path is defined in the Settings module as ``SERVICE_OBJECTS_FILENAME``.

File Format
~~~~~~~~~~~

The ``service_objects.csv`` file defines service objects that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single service object or a service object that belongs to a service group.

CSV Columns
^^^^^^^^^^^

+------------------+---------------------------------------------------------------+----------+---------------------------+
| Column Name      | Description                                                   | Required | Example                   |
+==================+===============================================================+==========+===========================+
| Name             | Name of the service object. If left empty, the name will be   | No       | ``web-http``              |
|                  | auto-generated as ``SVC-{protocol}-{port}``                   |          |                           |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Protocol         | Protocol used by the service (tcp or udp)                     | Yes      | ``tcp``                   |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Destination Port | Port number or port range                                     | Yes      | ``80``, ``3478-3481``     |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Description      | Optional description for the service object                   | No       | ``HTTP web traffic``      |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Tags             | Comma-separated list of tags to apply to the service object   | No       | ``web,standard``          |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Session Timeout  | Flag to indicate if session timeout should be overridden      | No       |                           |
| Override         |                                                               |          |                           |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Override Timeout | Custom timeout value if override is enabled                   | No       |                           |
+------------------+---------------------------------------------------------------+----------+---------------------------+
| Service Group    | Comma-separated list of service groups this service belongs to| No       | ``web-services``          |
| Name             |                                                               |          |                           |
+------------------+---------------------------------------------------------------+----------+---------------------------+

Usage Examples
~~~~~~~~~~~~~~

Basic Service Object
^^^^^^^^^^^^^^^^^^^^

To define a basic service object, you need to specify at least the Protocol and Destination Port:

.. code-block:: text

   ,tcp,80,HTTP web traffic,,,,

This will create a service object named ``SVC-tcp-80`` for TCP port 80 with the description "HTTP web traffic".

Named Service Object
^^^^^^^^^^^^^^^^^^^^

To create a service object with a custom name:

.. code-block:: text

   web-http,tcp,80,HTTP web traffic,,,,

Service Object with Tags
^^^^^^^^^^^^^^^^^^^^^^^^

To add tags to a service object:

.. code-block:: text

   web-http,tcp,80,HTTP web traffic,web,,,

Service Object in a Group
^^^^^^^^^^^^^^^^^^^^^^^^^

To add a service object to a service group:

.. code-block:: text

   web-http,tcp,80,HTTP web traffic,web,,,web-services

Multiple Service Groups
^^^^^^^^^^^^^^^^^^^^^^^

To add a service object to multiple service groups, use a comma-separated list:

.. code-block:: text

   web-http,tcp,80,HTTP web traffic,web,,,"web-services,internet-services"

Port Ranges
^^^^^^^^^^^

For services that use a range of ports:

.. code-block:: text

   ,udp,3478-3481,STUN port ranges for Skype/Teams,,,,

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The service objects defined in this CSV file are processed by the ``create_service_objects`` function in the ``service_objects.py`` module. This function:

1. Parses the CSV file using the ``parse_metadata_from_csv`` function
2. Creates service objects for each row in the CSV file
3. Auto-generates names for service objects if not provided
4. Creates service groups based on the Service Group Name column
5. Deploys the service objects and groups to the PAN-OS device using multi-config API calls
