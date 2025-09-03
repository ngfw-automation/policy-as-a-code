Function Reference
==================

This reference provides a complete catalog of all functions in the Policy-as-a-Code system, organized in a sleek table format by functionality.

Application Entry Points
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``main(**kwargs)``
     - Application entry point with menu system and deployment coordination
     - ``int`` (exit code)
     - `main.py <https://github.com/your-repo/policy-as-a-code/blob/main/main.py>`_
   * - ``deploy_policy(...)``
     - Orchestrates complete policy deployment workflow
     - ``int`` (exit code)
     - `main.py <https://github.com/your-repo/policy-as-a-code/blob/main/main.py>`_

Core Policy Engine
------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``build_policy(...)``
     - Executes 22-step policy construction algorithm
     - ``None``
     - `build_policy.py:205 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L205>`_
   * - ``discover_and_delete_policy_rules(...)``
     - Discovers and deletes existing policy rules with rollback capability
     - ``None``
     - `build_policy.py:55 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L55>`_

Policy Rule Creators
--------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``create_security_rules(...)``
     - Creates security policy rules from business requirements
     - ``None``
     - `build_policy.py:162 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L162>`_
   * - ``create_decryption_rules(...)``
     - Creates TLS inspection decryption rules
     - ``None``
     - `build_policy.py:169 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L169>`_
   * - ``create_nat_rules(...)``
     - NAT policy rule creation (future implementation)
     - ``None``
     - `build_policy.py:176 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L176>`_
   * - ``create_authentication_rules(...)``
     - Authentication policy rules (future implementation)
     - ``None``
     - `build_policy.py:184 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L184>`_
   * - ``create_override_rules(...)``
     - Application override rules (future implementation)
     - ``None``
     - `build_policy.py:191 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L191>`_
   * - ``create_pbf_rules(...)``
     - Policy-Based Forwarding rules (future implementation)
     - ``None``
     - `build_policy.py:198 <https://github.com/your-repo/policy-as-a-code/blob/main/lib/build_policy.py#L198>`_
   * - ``security_policy_pre(...)``
     - Generates security policy pre-rules
     - ``None``
     - `security_policy_pre.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/security_policy_pre.py>`_
   * - ``security_policy_post(...)``
     - Generates security policy post-rules
     - ``None``
     - `security_policy_post.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/security_policy_post.py>`_
   * - ``decryption_policy(...)``
     - Generates decryption policy rules from config files
     - ``None``
     - `decryption_policy.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/decryption_policy.py>`_

Business Requirements Processing
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``generate_app_categories_template(...)``
     - Extracts available App-ID categories for validation
     - ``None``
     - `template_generator.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/template_generator.py>`_
   * - ``generate_url_categories_template(...)``
     - Extracts available URL categories for validation
     - ``None``
     - `template_generator.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/template_generator.py>`_
   * - ``parse_app_categories(filename)``
     - Parses application category requirements from CSV/JSON
     - ``dict``
     - `category_parser.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/category_parser.py>`_
   * - ``parse_url_categories(filename)``
     - Parses URL category requirements from CSV/JSON
     - ``dict``
     - `category_parser.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/category_parser.py>`_

Object Management
-----------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``create_tags(...)``
     - Creates organizational and metadata tags
     - ``None``
     - `manage_tags.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/manage_tags.py>`_
   * - ``tag_applications(...)``
     - Applies metadata tags to applications
     - ``None``
     - `manage_tags.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/manage_tags.py>`_
   * - ``create_application_filters(...)``
     - Creates application filters from requirements
     - ``None``
     - `application_filters.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/application_filters.py>`_
   * - ``create_application_groups(...)``
     - Creates application groups referencing filters
     - ``None``
     - `application_groups.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/application_groups.py>`_
   * - ``handle_address_objects_and_groups(...)``
     - Delta-based synchronization of address objects
     - ``None``
     - `address_objects_staging.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/address_objects_staging.py>`_
   * - ``create_service_objects(...)``
     - Creates service objects and groups from config
     - ``None``
     - `service_objects.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/service_objects.py>`_
   * - ``create_edls(...)``
     - Deploys external dynamic lists with environment substitution
     - ``None``
     - `edls.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/edls.py>`_
   * - ``create_custom_url_categories(...)``
     - Creates custom URL categories from requirements
     - ``None``
     - `url_categories.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/url_categories.py>`_

Security Profile Management
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``create_security_profile_groups(...)``
     - Creates security profile groups for policy assignment
     - ``None``
     - `security_profile_groups.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/security_profile_groups.py>`_
   * - ``create_url_filtering_static_profiles(...)``
     - Creates URL filtering profiles from static JSON
     - ``None``
     - `security_profile_url_filtering.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/security_profile_url_filtering.py>`_
   * - ``create_url_filtering_auto_profiles(...)``
     - Auto-generates URL filtering profiles from requirements
     - ``None``
     - `security_profile_url_filtering.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/security_profile_url_filtering.py>`_
   * - ``create_log_forwarding_profiles(...)``
     - Creates comprehensive logging configuration profiles
     - ``None``
     - `log_forwarding_profiles.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/log_forwarding_profiles.py>`_
   * - ``import_custom_signatures(...)``
     - Imports custom app/vulnerability/spyware signatures
     - ``None``
     - `custom_objects.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/custom_objects.py>`_
   * - ``import_custom_response_pages(...)``
     - Imports environment-specific custom response pages
     - ``None``
     - `custom_objects.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/custom_objects.py>`_

Utility Functions
-----------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``load_menu_options()``
     - Loads deployment menu configuration
     - ``dict``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``display_menu()``
     - Displays interactive deployment menu
     - ``None``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``get_user_choice()``
     - Handles user input validation and selection
     - ``str``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``delete_objects(...)``
     - Bulk/individual object deletion with error handling
     - ``None``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``delete_non_sdk_objects(...)``
     - Deletes objects via direct API (non-SDK supported)
     - ``None``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``create_non_sdk_objects(...)``
     - Creates objects via direct API (non-SDK supported)
     - ``None``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_
   * - ``execute_multi_config_api_call(...)``
     - Executes bulk operations using multi-config XML
     - ``None``
     - `auxiliary_functions.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/auxiliary_functions.py>`_

Integration and External Systems
---------------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Function**
     - **Description**
     - **Returns**
     - **Source**
   * - ``generate_categories_for_servicenow(...)``
     - Generates category mappings for ServiceNow integration
     - ``None``
     - `service_now.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/service_now.py>`_

Configuration Management
------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 40 15 25

   * - **Component**
     - **Description**
     - **Type**
     - **Source**
   * - ``settings.py``
     - Global configuration: paths, toggles, deployment flags
     - ``module``
     - `settings.py <https://github.com/your-repo/policy-as-a-code/blob/main/settings.py>`_
   * - ``rich_output.py``
     - Rich console formatting utilities for enhanced UX
     - ``module``
     - `rich_output.py <https://github.com/your-repo/policy-as-a-code/blob/main/lib/rich_output.py>`_
