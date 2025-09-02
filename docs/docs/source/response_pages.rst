Response Pages
==============

This document explains how response pages are generated and customized in the NGFW system.

Overview
--------

Response pages are HTML pages displayed to users when the NGFW blocks access to content. 
These pages provide information about why the content was blocked and may offer options 
for requesting access or reporting misclassifications.

The system uses a combination of YAML configuration files and Jinja2 templates to generate 
dynamic, customizable response pages that adapt to different blocking scenarios.

Directory Structure
-------------------

Response pages are organized in the ``ngfw/device/response pages`` directory:

.. code-block:: text

   ngfw/device/response pages/
   ├── lab/                      # Lab/testing environment
   │   ├── configs/              # YAML configuration files
   │   │   ├── url-block-page.yaml
   │   │   ├── file-block-page.yaml
   │   │   └── ...
   │   ├── templates/            # Jinja2 templates
   │   │   ├── base.html.j2
   │   │   ├── url-block-page.html.j2
   │   │   └── ...
   │   └── shared.yaml           # Shared configuration
   └── prod/                     # Production environment (similar structure)

Page Generation Algorithm
-------------------------

Response pages are generated through a multi-step process that combines configuration data, 
templates, and dynamic content. Here's how the algorithm works:

1. **Configuration Loading**:
   
   * The system loads the page-specific YAML configuration file (e.g., ``url-block-page.yaml``)
   * It also loads the shared configuration (``shared.yaml``)
   * These configurations are merged, with page-specific values taking precedence

2. **Template Selection**:
   
   * The system selects the appropriate Jinja2 template based on the page type
   * Most page templates extend the base template (``base.html.j2``)

3. **Template Rendering**:
   
   * The Jinja2 template is rendered with values from the configuration
   * This creates the basic HTML structure with placeholders for dynamic content

4. **Dynamic Content Processing**:
   
   * When the page is displayed to a user, JavaScript in the template:
     * Extracts values from Palo Alto Networks' placeholders (like ``<url/>``, ``<category/>``)
     * Evaluates conditional blocks based on the extracted values
     * Selects the appropriate message based on matching conditions
     * Replaces variables in the message with actual values
     * Updates the DOM to display the final content

5. **User Interaction**:
   
   * The page may include forms or links for user actions (requesting access, etc.)
   * These forms typically submit to a service desk or ticketing system

Jinja2 Templating Details
-------------------------

The system uses Jinja2 templating to create the HTML structure of response pages. 
Here's how the templating works:

Base Template
~~~~~~~~~~~~~

The ``base.html.j2`` template defines the overall structure of all response pages:

.. code-block:: html+jinja

   <!DOCTYPE html>
   <html lang="en">
   <head>
     <meta charset="UTF-8">
     <title>{{ title }}</title>
     <style>{{ css }}</style>
     {% block head_extra %}{% endblock %}
   </head>
   <body>
     <div id="content">
       <!-- Company header -->
       <div class="banner">
         <span class="brand">{{ firm_name }}</span>
         <span class="infosec">{{ infosec_label }}</span>
       </div>

       <!-- Main response area -->
       <div class="response">
         <h1 id="headingText">{{ default_heading }}</h1>
         <p id="warningText">{{ default_message }}</p>
         {% block extra_body %}{% endblock %}
       </div>

       <!-- Summary panel -->
       {% block summary %}
       <div class="summary">
         <!-- Summary content -->
       </div>
       {% endblock %}
     </div>

     <!-- JavaScript for dynamic content -->
     <script>
       // Process conditional blocks
       {% if conditional_blocks|length %}
         {% for b in conditional_blocks %}
           // Condition evaluation and content update
         {% endfor %}
       {% endif %}
     </script>
   </body>
   </html>

Page-Specific Templates
~~~~~~~~~~~~~~~~~~~~~~~

Page-specific templates extend the base template and can override blocks to customize behavior:

.. code-block:: html+jinja

   {% extends "base.html.j2" %}

   {% block head_extra %}
   <!-- Additional head content -->
   {% endblock %}

   {% block summary %}
   <!-- Override or remove summary panel -->
   {% endblock %}

   {% block extra_body %}
   <!-- Additional body content -->
   {% endblock %}

Conditional Logic
~~~~~~~~~~~~~~~~~

The system uses JavaScript to evaluate conditions and display appropriate content:

.. code-block:: javascript

   // Extract values from PAN-OS placeholders
   const url = clean("<url/>");
   const category = clean("<category/>");
   
   // Evaluate conditions from YAML config
   if (category.includes("web-based-email")) {
     document.getElementById("headingText").textContent = "Compliance warning";
     document.getElementById("warningText").innerHTML = 
       "For your security and data protection, access to personal web-mail sites is prohibited...";
   } else if (/* other conditions */) {
     // Handle other cases
   } else {
     // Use fallback content
   }

Customizing Response Pages
--------------------------

Organizations can customize response pages to match their branding, policies, and requirements.

Customization Options
~~~~~~~~~~~~~~~~~~~~~

1. **Shared Configuration**:
   
   Modify ``shared.yaml`` to update:
   
   * Organization name and labels
   * Service desk URLs
   * CSS styling
   * Common messages

2. **Page-Specific Configuration**:
   
   Edit YAML files in the ``configs/`` directory to customize:
   
   * Page titles and default messages
   * Conditional logic for different scenarios
   * Service desk form IDs

3. **Templates**:
   
   For more advanced customization, modify the templates:
   
   * Update ``base.html.j2`` to change the overall structure
   * Modify page-specific templates for special cases

Example: Customizing URL Block Page
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here's an example of customizing the URL block page:

1. **Update shared.yaml**:

   .. code-block:: yaml

      firm_name: Acme Corporation
      infosec_label: Information Security
      servicedesk_base: https://acme.service-now.com/sp?id=sc_cat_item&sys_id=
      css: |
        body { background:#f0f2f5; font-family:Arial,Helvetica,sans-serif; }
        .banner { background:#003366; color:#fff; }
        /* Additional custom CSS */

2. **Modify url-block-page.yaml**:

   .. code-block:: yaml

      title: "Acme Corporation - Access Restricted"
      default_heading: "Website Access Restricted"
      default_message: |
        This website has been blocked according to Acme Corporation's security policy.
        If you need access for business purposes, please use the link below.
      
      conditional_blocks:
        - match: category
          operator: includes
          value: social-networking
          heading: "Social Media Access Restricted"
          message: |
            Access to social media sites is limited during business hours.
            If you need access for business purposes, please submit a request.

3. **Create a custom template** (optional):

   .. code-block:: html+jinja

      {% extends "base.html.j2" %}
      
      {% block head_extra %}
      <link rel="icon" href="https://acme.com/favicon.ico">
      {% endblock %}
      
      {% block extra_body %}
      <div class="acme-footer">
        <img src="https://acme.com/logo.png" alt="Acme Corporation">
      </div>
      {% endblock %}

Best Practices
~~~~~~~~~~~~~~

When customizing response pages:

1. **Maintain consistency** across all pages for a professional user experience
2. **Use clear, concise language** to explain why content was blocked
3. **Provide actionable options** for users who need legitimate access
4. **Test thoroughly** in a lab environment before deploying to production
5. **Consider accessibility** by using appropriate contrast, font sizes, etc.
6. **Keep branding subtle** to maintain focus on the security message

By following these guidelines, organizations can create effective, branded response pages 
that communicate security policies while providing a good user experience.