.. _introduction:

Introduction
============

This documentation supports the open-source project
`Policy as Code <https://github.com/ngfw-automation/policy-as-a-code>`_ and serves as a hands-on companion to the book
*Palo Alto Networks from Policy to Code*
(`Packt Publishing <https://www.packtpub.com/en-gb/product/palo-alto-networks-from-policy-to-code-9781835881293>`_).

Project Overview
----------------

The **NGFW Policy as Code** project demonstrates how to manage Palo Alto Networks next-generation firewall (NGFW) policies
like software: by writing them in code, storing them in version control, and deploying them automatically.
Instead of spending hours in the GUI making manual edits, you can define your policy once in Python and push a complete
configuration to your firewall or Panorama.

The example setup focuses on a common enterprise scenario: a Palo Alto Networks firewall acting as the Internet gateway.
From there, the project builds out everything the firewall needs to enforce a web-filtering policy:

- Security and decryption rules
- Address and service objects and groups
- Application filters and groups
- URL categories and external dynamic lists
- Security and decryption profiles
- Data patterns
- Custom threat and vulnerability signatures
- Automated response to security incidents
- Integration with service desk workflows via advanced response pages

This approach makes policy changes easier to repeat, test, and audit. It also reduces day-to-day maintenance by relying
on reusable objects and automation that embraces dynamic content updates and category-based business requirements,
rather than constantly making one-off manual rule changes.

Learn More in the Companion Book
--------------------------------

These docs are meant to get you started with the code. If you want the bigger picture—including background, design principles,
and complete workflows — the book *Palo Alto Networks from Policy to Code* provides the full context.

It starts with how NGFWs work and the problems teams run into when managing them manually. It then covers policy building
blocks - connection matching and processing, logging, profiles, and design practices - before moving on to automation. You’ll see how to set up
a Python development environment, use the PAN-OS SDK and XML API, and handle more advanced cases like debugging and customizations.

The final chapters focus on real-world operations: testing policies before rollout, dealing with exceptions, running pilot
cutovers, and keeping deployments consistent across environments.

If you’re coming from a firewall, networking, or DevOps background and want to apply automation to NGFW policy management,
the book provides the context and step-by-step examples that complement this project.

.. warning::
   This documentation is a work in progress and may not yet cover all features.
