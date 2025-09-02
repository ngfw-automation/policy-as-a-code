.. _architecture:

Architecture
============

This section provides a very high-level overview of the project architecture, explaining how the different components
work together to generate and deploy a firewall policy.

Component Diagram
-----------------

The project consists of several key components:

1. **Static Policy Rules**  - Definitions for static policy rules (these rules are placed at the beginning of the rulebase; in Panorama-based deployments this corresponds to the PRE section of the target device group)
2. **Dynamic Policy Rules** - Prescribed via CSV files that define policy behaviour for standard App-ID and URL categories (these rules are placed at the bottom of the rulebase; in Panorama-based deployments this corresponds to the POST section of the target device group)
3. **Policy Targets**       - JSON file that defines possible targets for policy deployment. A target can be either:

   - a combination of a standalone firewall address, VSYS name, and a deployment type **OR**
   - a combination of a Panorama address, device group, template, and a deployment type

4. **Object Definitions** - CSV/JSON/YAML/XML files that define all objects referenced in the policy rules (address objects, service objects, etc.)
5. **Deployment Engine** - Handles the communication with Palo Alto Networks devices
6. **Auxiliary Functions** - Helper functions for various tasks

.. graphviz:: ../diagrams/architecture.dot

Policy formation
----------------

The resulting security policy is formed as follows:

.. graphviz:: ../diagrams/security-policy-formation.dot

The resulting decryption policy is formed as follows:

.. graphviz:: ../diagrams/decryption-policy-formation.dot

.. note::
   When the policy is deployed directly to a firewall, its structure mirrors a Panorama deployment.
   Rules that would normally go into the ```PRE``` section of a Panorama device group are placed at the top of the firewall policy,
   while rules from the ```POST``` section are placed at the bottom of the firewall policy.