Current Panorama-Focused Deployment Components
----------------------------------------------

In the existing tool, policy deployment is handled by a few key modules and functions
designed for Panorama (or standalone PAN-OS firewalls). Notably:

-  **CLI/Main:** ``main.py`` drives deployment. It loads target
   definitions from **``policy_targets.json``**, prompts the user to
   select a target, and then calls ``deploy_policy()`` with the chosen
   target's settings. The code distinguishes Panorama vs. firewall by
   instantiating either a ``Panorama`` or ``Firewall`` object from the
   PAN-OS SDK. For Panorama targets, it expects a **device group** and
   **template** name; for firewalls, a VSYS.

-  **Deployment Orchestrator:** ``lib/build_policy.py`` contains the
   core ``build_policy()`` function which orchestrates connecting to the
   device and pushing the config. This function currently assumes a
   PAN-OS device interface (Panorama or firewall) is available via the
   pan-os SDK. It sets up the policy scope by attaching a
   **DeviceGroup** and **Template** to the Panorama object (or a
   **Vsys** to a Firewall) to represent the target container for rules.
   It then acquires Panorama configuration locks, deletes existing
   rules, and builds new rules and objects. For Panorama, it creates
   separate Pre- and Post- rulebases (``PreRulebase``/``PostRulebase``
   attached under the DeviceGroup) whereas for a firewall it uses a
   single rulebase. Finally, it converts all staged rules/objects into a
   single XML API "multi-config" request and executes it via the PAN-OS
   XML API. (The function ``execute_multi_config_api_call`` uses the
   device's XAPI to push the combined XML config in one go.) The script
   does **not** commit the config – it leaves that step for the user on
   Panorama's side.

-  **Policy Building Modules:** Supporting modules like
   ``lib/security_policy_pre.py``, ``lib/security_policy_post.py``,
   ``lib/decryption_policy.py``, etc., construct the rule objects (using
   the pan-os SDK classes like ``SecurityRule``, ``DecryptionRule``)
   based on input files. They handle differences between Panorama
   vs. firewall (e.g. omitting Panorama-specific fields like rule target
   on standalone firewalls). Similarly, object creation utilities
   (``lib/manage_tags.py`` for tags, ``lib/address_objects_staging.py``
   for addresses/groups, ``lib/url_categories.py`` for custom URLs,
   etc.) use the SDK to create and add objects to the device
   configuration in code. All these ultimately rely on the
   Panorama/Firewall object's context to add config, which is later
   pushed via the multi-config API call.