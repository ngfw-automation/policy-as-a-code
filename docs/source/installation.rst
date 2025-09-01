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

