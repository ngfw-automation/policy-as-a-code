Data Patterns
=============

Data patterns define patterns for data filtering profiles.

File Location
~~~~~~~~~~~~~

Data patterns are defined in files located in:

.. code-block:: text

   ngfw/objects/custom objects/data patterns

This path is defined in the ``settings.py`` module as ``DATA_PATTERNS_FOLDER``.

File format
~~~~~~~~~~~

Applications must be defined in idividual JSON or YAML files.
Create a data pattern in the PAN-OS administrative UI, export it as XML,
convert to YAML or JSON and save to the
``ngfw/objects/custom objects/data patterns`` folder.

Here is an example in the YAML format:

.. code-block:: yaml

    entry:
      '@name': AIP-Confidential-Excel
      pattern-type:
        file-properties:
          pattern:
            entry:
            - '@name': AIP Excel - Confidential
              file-type: aip-encrypted-xlsx
              file-property: panav-rsp-office-dlp-msip-label
              property-value: 33333333-3333-3333-3333-333333333333
            - '@name': Excel - Confidential
              file-type: xlsx
              file-property: panav-rsp-office-dlp-msip-label
              property-value: 33333333-3333-3333-3333-333333333333
