Custom URL Categories
=====================

Custom URL categories allow you to define your own URL categories for use in security policy rules. They can be based on specific URLs or patterns, or they can reference predefined PAN-OS URL categories.

File Location
~~~~~~~~~~~~~

Custom URL categories are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/custom objects/url category/custom-url-categories.csv

This path is defined in the ``settings.py`` module as ``CUSTOM_URL_CATEGORIES_FILENAME``.

File Format
~~~~~~~~~~~

Each row in the CSV file represents a URL or pattern that belongs to a custom URL category.

.. list-table:: CSV Columns
   :header-rows: 1
   :widths: 18 46 10 26

   * - Column Name
     - Description
     - Required
     - Example
   * - Name
     - Name of the custom URL category
     - Yes
     - ``UCL-acme-generic-app``
   * - Type
     - Type of category (List or Match)
     - Yes
     - ``List``
   * - Description
     - Optional description for the category
     - No
     - ``This category covers all URLs in ACME domains and subdomains``
   * - Sites
     - URL, pattern, predefined category, or HTTPS link to a remote text file (one entry per line; HTTPS only)
     - Yes
     - ``example.com/``, ``computer-and-internet-info``, ``https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/any/optimize/url``

Usage Examples
~~~~~~~~~~~~~~

Basic Custom URL Category
^^^^^^^^^^^^^^^^^^^^^^^^^

To define a basic URL List category:

.. code-block:: text

   UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/

Custom URL Category Types
^^^^^^^^^^^^^^^^^^^^^^^^^

Custom URL categories can be of two types:

1. **URL List** - Contains specific URLs or patterns:

   .. code-block:: text

      UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
      UCL-acme-generic-app,List,,*.example.com/

2. **Category Match** - References predefined PAN-OS URL categories:

   .. code-block:: text

      UCM-comp-inet-info_low-risk,Match,,computer-and-internet-info
      UCM-comp-inet-info_low-risk,Match,,low-risk

Multiple URLs in a Category
^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can add multiple URLs to the same category by repeating the category name in multiple rows:

.. code-block:: text

   UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
   UCL-acme-generic-app,List,,*.example.com/
   UCL-acme-generic-app,List,,example.net/
   UCL-acme-generic-app,List,,*.example.net/

Remote URL Lists (HTTPS only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can populate a URL List category from a remote text file served over HTTPS. Put the HTTPS link into the Sites column; the tool downloads it, reads non-empty lines, lowercases and trims them, and uses them as the category entries.

.. code-block:: text

   UCL-m365-worldwide-any-optimize,List,This category includes URLs from M365 Worldwide Any Optimize category,https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/any/optimize/url

Notes:

- HTTPS is required. HTTP is not fetched and will be treated as a literal string.
- TLS verification uses settings.CERTIFICATE_BUNDLE_FILENAME.
- If both inline Sites and an HTTPS link are provided for the same Name, the HTTPS list replaces the inline entries.
- If multiple HTTPS links are listed for the same Name, the last one wins.

.. tip::
   Remote lists are great when you maintain URLs externally or consume vendor feeds that
   change rarely and therefore do not have to consume precious EDL capacity.

   Make sure the URL is reachable from the system running this tool and rerun deployment
   when the remote list changes.

Implementation Notes
~~~~~~~~~~~~~~~~~~~~

Processed by ``create_custom_url_categories`` in ``lib/url_categories.py``.

- CSV parsing: ``parse_metadata_from_csv`` defined in ``settings.CUSTOM_URL_CATEGORIES_FILENAME``.
- Deduplication: by Name only (first Type wins). Keep Type consistent across rows for the same Name.
- Description: last non-empty Description for a Name is used.
- Sites handling:

  - Inline entries are lowercased and trimmed; duplicates are not removed.
  - HTTPS URL in Sites downloads a remote list (TLS verified via ``settings.CERTIFICATE_BUNDLE_FILENAME``); non-empty lines are lowercased and replace any previously collected inline entries. If multiple HTTPS sources exist, the last one wins. HTTP is not fetched.

- Accepted Type values (case-insensitive): List or URL List; Match or Category Match.
- Deployment: objects created and pushed via a multi-config API call.
