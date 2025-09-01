Custom URL Categories
=====================

Custom URL categories allow you to define your own URL categories for use in security policy rules. They can be based on specific URLs or patterns, or they can reference predefined PAN-OS URL categories.

File Location
~~~~~~~~~~~~~

Custom URL categories are defined in the CSV file located at:

.. code-block:: text

   ngfw/objects/custom objects/url category/custom-url-categories.csv

This path is defined in the Settings module as ``CUSTOM_URL_CATEGORIES_FILENAME``.

File Format
~~~~~~~~~~~

The ``custom-url-categories.csv`` file defines custom URL categories that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a URL or pattern that belongs to a custom URL category.

CSV Columns
^^^^^^^^^^^

+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Column Name      | Description                                                   | Required | Example                                  |
+==================+===============================================================+==========+==========================================+
| Name             | Name of the custom URL category                               | Yes      | ``UCL-acme-generic-app``                 |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Type             | Type of category (List or Match)                              | Yes      | ``List``                                 |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Description      | Optional description for the category                         | No       | ``This category covers all URLs in ACME  |
|                  |                                                               |          | domains and subdomains``                 |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+
| Sites            | URL, pattern, or predefined category to include               | Yes      | ``example.com/``,                        |
|                  |                                                               |          | ``computer-and-internet-info``           |
+------------------+---------------------------------------------------------------+----------+------------------------------------------+

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

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The custom URL categories defined in this CSV file are processed by the ``create_custom_url_categories`` function in the ``url_categories.py`` module. This function:

1. Parses the CSV file using the ``parse_metadata_from_csv`` function
2. Builds a deduplicated list of custom categories based on their names and types
3. Processes each category:
   - Extracts the description (using the last non-empty description for each category)
   - Builds a list of URLs or categories for each custom category
   - Handles remote HTTP/HTTPS sources for URL lists
4. Creates custom URL category objects using the Palo Alto Networks SDK:
   - URL List type categories with specific URLs or patterns
   - Category Match type categories referencing predefined PAN-OS URL categories
5. Deploys the custom URL categories to the PAN-OS device using multi-config API calls
