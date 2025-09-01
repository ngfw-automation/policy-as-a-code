.. _customization:

Customization
=============

This section provides instructions for customizing the project to suit your environment.


Minimally required customization
--------------------------------

After installation, you need to configure the project:

1. Update global environment-specific constants in the ``settings.py`` file:

   .. important::
       At a minimum, the zone names must be updated to match your environment.

2. Specify the policy target(s) in the ``requirements/policy_targets.json`` file:

   A target can take one of the two possible forms:

   - for Panorama-based targets:

        - Panorama address
        - device group
        - template
        - type of the target environment

   - for firewall-based targets:

        - firewall address
        - VSYS
        - type of the target environment

.. hint::
    It's a good idea to **ALWAYS** include a non-production firewall or Panorama instance as one of the possible targets
    for policy deployment. You can have as many targets as you want. The script would then deploy the policy to one
    target of your choice at a time.

3. Update the rules and object definitions in ``ngfw/objects`` folder as required

4. Ensure all prerequisites and dependencies are met (these items are not configured by the script):

   - NAT rule(s)
   - User-ID subsystem
   - Forward Trust certificate for TLS inspection

5. Modify Jinja templates for response pages. The templates are in the ``ngfw/device/response pages`` folder.


External Dependencies
---------------------

- **Service Desk workflows** – You’ll need to create the necessary workflows in your Service Desk system.
  This project doesn’t cover that part, but as you customize the response pages, you’ll identify the use cases
  that require workflow integration.

- **EDL hosting infrastructure** – The firewall policy can reference external dynamic lists (EDLs).
  These must be hosted somewhere in your environment. While you can choose not to use EDLs at all,
  doing so will make it much harder to handle policy exceptions quickly.

- **Root CA distribution** – The root certificate authority (CA) that issued the CA certificate used
  for the Forward Trust certificate must be installed on all client devices.


Advanced Customization Topics
-----------------------------

.. toctree::
   :maxdepth: 2

   defaults
   input_data_formats
   response_pages
