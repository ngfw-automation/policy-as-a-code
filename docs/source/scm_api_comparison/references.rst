References
----------

* Palo Alto Networks, *Strata Cloud Manager API Documentation* – Official developer docs detailing SCM's API structure, including functional REST endpoints for security policy and objects.
* Palo Alto Networks, *PAN-OS / Panorama API Documentation* – Guides for Panorama's XML API usage (e.g., generating API keys and commit operations) and PAN-OS REST.
* Palo Alto Networks, *Strata Cloud Manager – Getting Started Guide* – Explains the Push Config process in SCM (activating changes on firewalls).
* Matt Blackwell, *Mastering Policy Flexibility in SCM* – Blog highlighting differences in configuration scope between Panorama and SCM (folders vs. device groups, snippets vs. templates) and noting that SCM's feature parity with Panorama is still evolving.
* Palo Alto Networks, *panos-to-scm Migration Tool (README)* – Notes from the official migration script pointing out current API limitations (e.g., requirement of profile groups, lack of schedule support in policy API).
* Palo Alto Networks, *PAN-OS Python SDK and Cloud Management SDK* – Developer resources indicating that the traditional ``pan-os-python`` SDK targets PAN-OS/Parorama, whereas new tools (e.g., ``pan-scm-sdk``) are available for SCM. These resources guide how to adapt or replace your SDK usage when moving to SCM.