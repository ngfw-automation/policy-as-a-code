Strata Cloud Manager (SCM)
==========================

.. note::
   The project currently does not support Strata Cloud Manager as a deployment target. This section provides ideas and guidance on how this integration could be implemented based on the API capabilities of SCM and PAN-OS platforms.

   For detailed information on SCM integration possibilities, see :doc:`scm_integration_details/index`.

   For a comparative analysis of API capabilities between SCM and Panorama, see :doc:`scm_api_comparison/index`.

Introduction
------------

Strata Cloud Manager (SCM) is Palo Alto Networks' cloud-based management solution for their security products. While the current project is focused on Panorama-based deployments, adapting it to support SCM as a deployment target would enable users to leverage cloud-based management capabilities.

The integration would require significant changes to the authentication, API interaction, and deployment processes, but the core policy generation logic could largely be reused. The following pages provide detailed information on how such an integration could be implemented and the differences between SCM and Panorama APIs that would need to be addressed.

Contents
--------

.. toctree::
   :maxdepth: 2

   scm_api_comparison/index
   scm_integration_details/index
