.. _architecture:

Architecture
============

This section provides an overview of the project architecture, explaining how the different components work
together to generate and deploy a firewall policy.

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

Data Flow
---------

The data flow through the system follows these steps:

1. **Input Processing**: The system reads policy requirements from JSON and CSV files
2. **Object Generation**: Based on the requirements, the system generates necessary objects
3. **Policy Generation**: Using the objects and requirements, the system builds security and decryption policies
4. **Validation**: The generated policies and objects are validated for correctness
5. **Deployment**: The validated policies and objects are deployed to the target device(s)

.. code-block:: text

    Requirements → Object Generation → Policy Generation → Validation → Deployment

Integration Points
------------------

The NGFW Policy as Code project integrates with Palo Alto Networks devices in the following ways:

1. **PAN-OS XML API**: Used for deploying policies and objects to firewalls and Panorama
2. **Configuration Files**: Can export configurations to files for manual import

The project is designed to be extensible, allowing for integration with other systems:

1. **CI/CD Pipelines**: Can be integrated into continuous integration/deployment workflows
2. **Source Control**: Policy definitions can be stored in version control systems
3. **Custom Deployment Targets**: The architecture allows for adding new deployment targets

Extension Points
----------------

The NGFW Policy as Code project can be extended in several ways:

1. **Custom Objects**: New object types can be added by creating new Python modules
2. **Custom Policies**: New policy types can be added by creating new Python modules
3. **Custom Deployment Methods**: New deployment methods can be added by extending the deployment engine
4. **Custom Validation Rules**: New validation rules can be added to ensure policy correctness

Future enhancements may include:

1. **API Gateway**: REST API for programmatic policy generation
2. **Web Interface**: GUI for policy management
3. **Additional Deployment Targets**: Support for cloud-based deployments