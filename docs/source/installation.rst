.. _installation:

Installation
============

This section provides detailed instructions for installing and configuring the project.

System Requirements
-------------------

Before installing the project, ensure your system meets the following requirements:

* **Python**: Version 3.11, 3.12 or 3.13 (likely to work with later versions too but this has not been tested)
* **Operating System**: Windows, macOS, or Linux
* **Disk Space**: At least 500MB of free disk space (most of this space would be consumed by Python's ``.venv`` folder, not the code itself)
* **Network**: access to a licenced Palo Alto Networks firewall(s) or Panorama appliance with a `currently supported version  of PAN-OS <https://www.paloaltonetworks.co.uk/services/support/end-of-life-announcements/end-of-life-summary#pan-os-panorama>`_
* **Permissions**: Administrative access to the target firewall(s) or Panorama

.. warning::
    Using Python versions eralier than 3.11 may lead to unexpected behavior or errors.

Installation Methods
--------------------

There are several ways to install and run the project code:

Method 1: Using locally provisioned Python, pip and git
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Ensure you have `Python`, `pip` and `git` installed.
2. (optional) It's recommended to install an IDE such as `PyCharm <https://www.jetbrains.com/pycharm/download/>`_ or `VisualStudio Code <https://code.visualstudio.com/download>`_
3. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/ngfw-automation/nextgen-policy.git
       cd nextgen-policy

4. Install the required packages:

   .. code-block:: bash

       pip install --upgrade pip
       pip install --no-cache-dir -r requirements.txt
       pip install pan-python==0.25.0

5. :doc:`Customise <customization>` the project according to your requirements. This step is **very important**, do not skip it.
6. Run ``main.py``:

   .. code-block:: bash

       python main.py

.. hint::
    It's a good idea to **ALWAYS** target a non-production firewall or Panorama instance first to test the policy.


Method 2: Using Docker
~~~~~~~~~~~~~~~~~~~~~~

The project includes a Dockerfile that can be used to build a container.
Below are the instructions for Windows.

1. Install and configure `WSL <https://learn.microsoft.com/en-us/windows/wsl/install>`_
2. Install `Docker Desktop <https://docs.docker.com/desktop/setup/install/windows-install/>`_
3. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/ngfw-automation/nextgen-policy.git
       cd nextgen-policy

4. :doc:`Customise <customization>` the project according to your requirements. This step is **very important**, do not skip it.
5. Use PowerShell CLI to navigate to the folder that contains the code
6. Build the container:

   .. code-block:: bash

       docker build -t ngfw-policy-as-code .

7. Run the container:

   .. code-block:: bash

       docker run -it ngfw-policy-as-code


Method 3: Customization with Docker Compose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also pull the latest pre-built image, customize the defaults and run it. This method does not require
you to pull the repository with the source code or install *PyCharm*, *Python* and *Git*.

Follow the steps below (all commands assume you run this in **PowerShell** on **Windows**):

.. note::
   These instructions assume you have `Docker Desktop <https://www.docker.com/products/docker-desktop/>`__ installed and working.

Step 1. Create an empty folder
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Open PowerShell and create a new folder for your work:

.. code-block:: powershell

   mkdir C:\temp\palo
   cd C:\temp\palo

.. tip::
   You can use any path you like instead of ``C:\temp\palo``.

Step 2. Create the docker-compose.yaml
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Inside your new folder, create a file named ``docker-compose.yaml`` with the following content:

.. code-block:: yaml

   services:
     app:
       image: ngfwautomation/ngfw-policy-as-code:latest
       working_dir: /app
       stdin_open: true
       tty: true
       pull_policy: always
       volumes:
         # Inputs (editable on host)
         - ./requirements:/app/requirements
         - ./migration:/app/migration
         - ./testing:/app/testing
         - ./misc:/app/misc
         - ./ngfw:/app/ngfw
         - ./settings.py:/app/settings.py
         # Logs and export
         - ./logs:/app/logs
         - ./export:/app/export
         - ./export/servicedesk:/app/export/servicedesk

.. warning::
   Indentation is **critical** in YAML. Make sure spaces are used (not tabs).

Step 3. Seed the folders
^^^^^^^^^^^^^^^^^^^^^^^^

The container comes with default input files. Before running, copy them to your host.

.. code-block:: powershell

   $cid = docker create ngfwautomation/ngfw-policy-as-code:latest

   docker cp "${cid}:/app/requirements/." .\requirements
   docker cp "${cid}:/app/migration/."    .\migration
   docker cp "${cid}:/app/testing/."      .\testing
   docker cp "${cid}:/app/misc/."         .\misc
   docker cp "${cid}:/app/ngfw/."         .\ngfw
   docker cp "${cid}:/app/settings.py"    .\settings.py

   docker rm $cid

After this step, your host will have ``requirements/``, ``migration/``, ``testing/``, ``misc/``, and ``settings.py``
populated with defaults from the container image.

Step 4. Edit configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

:doc:`Customise <customization>` the project according to your requirements.

.. important::
    This step is **very important**, do not skip it.

As a **minimum**:

1. Edit targets in ``requirements/policy_targets.json`` (firewall or Panorama details).
2. Edit the ``settings.py`` file to ensure that the *INSIDE* and *OUTSIDE* zones match the corresponding
   zone names on your target firewall(s). These values are case-sensitive:

.. code-block:: python

    # =================================================================================
    # Zone names referenced in the policy rules
    # =================================================================================

    ZONE_INSIDE             = 'INSIDE'
    ZONE_OUTSIDE            = 'OUTSIDE'


Step 5. Run the container
^^^^^^^^^^^^^^^^^^^^^^^^^

Start the container with:

.. code-block:: powershell

   docker compose run -it app

You will see an interactive menu of the policy deployment script.

.. tip::
   - To stop the container, press ``Ctrl+C``.

