"""
Functions for creating and managing URL filtering security profiles in PAN-OS.

This module provides functionality to:
- Create static URL filtering profiles from JSON configuration files
- Generate dynamic URL filtering profiles based on business requirements
- Configure different actions for URL categories (alert, allow, block, continue, override)
- Set up User Credential Submission (UCS) enforcement settings
- Validate URL categories against current PAN-OS URL categories
- Configure logging options for HTTP headers and container pages
- Support safe search enforcement settings
- Deploy profiles to PAN-OS devices using multi-config API calls
"""

import sys
from panos.panorama import Panorama
import settings
import os.path
from lib.auxiliary_functions         import parse_metadata_from_json, execute_multi_config_api_call
from rich import print


def create_url_filtering_static_profiles(profile_container, current_url_categories, panos_device):
    """
    Analyzes URL filtering profiles and creates static URL filtering security profiles on a PAN-OS device.
    The function reads JSON files from a specified directory, validates their content against the given
    URL categories, and generates configuration XML to define security profile objects.

    The function ensures that every category in a profile is matched to valid URL categories. It performs
    checks to avoid category duplication within a single profile/action and provides warnings for invalid or
    undefined categories. Additionally, User Credential Submission (UCS) actions for categories are handled,
    with validations similar to standard URL category actions.

    Args:
        profile_container: Device Group or VSYS object where the URL filtering profiles will be created.
        current_url_categories: A list of valid URL categories to validate against the definitions in the input profiles.
        panos_device: Firewall or Panorama device object.
    """
    print("Staging static URL-filtering profiles:")
    panos_device.add(profile_container)
    # first, we initialize the multi-config XML and the action_id
    action_id = 1
    multi_config_xml = '<multi-config>'

    # List all files in the given folder and analyze only JSON files
    for file_name in os.listdir(settings.SECURITY_PROFILES_URL_FILTERING_FOLDER):
        if file_name.endswith('.json'):  # Checks for .json extension
            file_path = os.path.join(settings.SECURITY_PROFILES_URL_FILTERING_FOLDER, file_name)
            if os.path.isfile(file_path):

                # read JSON data from the file
                profile = parse_metadata_from_json("URL-filtering profile", file_path)

                if profile is not None:
                    print(f"\tAnalyzing profile: {profile['name']}")
                    obj_xpath = profile_container.xpath() + "/profiles/url-filtering/entry[@name='" + profile['name'].strip() + "']"
                    # now we construct the "element" defining details of the object referenced by the XPATH

                    # We create a copy of categories to ensure each category is used only once
                    category_list_for_validation = current_url_categories.copy()
                    # first of all, we construct the XPATH component of our API call
                    # Categories per security action
                    alert = ""
                    if "alert" in profile:
                        for a1 in profile['alert']:
                            a1 = a1.strip()
                            if a1 in current_url_categories:
                                alert = alert + "<member>" + a1 + "</member>"
                                if a1 in category_list_for_validation:
                                    category_list_for_validation.remove(a1)
                                else:
                                    print(f"\t\tCategory '{a1}' is specified more than once. Correct profile definition!")
                                    sys.exit(1)
                            else:
                                print(f"\t\tCategory '{a1}' is invalid and will be skipped (check the spelling)")

                    if alert != "": alert = "<alert>" + alert + "</alert>"

                    allow = ""
                    if "allow" in profile:
                        for a2 in profile['allow']:
                            a2 = a2.strip()
                            if a2 in current_url_categories:
                                allow = allow + "<member>" + a2 + "</member>"
                                if a2 in category_list_for_validation:
                                    category_list_for_validation.remove(a2)
                                else:
                                    print(f"\t\tCategory '{a2}' is specified more than once. Correct profile definition!")
                                    sys.exit(1)
                            else:
                                print(f"\t\tCategory '{a2}' is invalid and will be skipped (check the spelling)")

                    if allow != "": allow = "<allow>" + allow + "</allow>"

                    block = ""
                    if "block" in profile:
                        for b in profile['block']:
                            b = b.strip()
                            if b in current_url_categories:
                                block = block + "<member>" + b + "</member>"
                                if b in category_list_for_validation:
                                    category_list_for_validation.remove(b)
                                else:
                                    print(f"\t\tCategory '{b}' is specified more than once. Correct profile definition!")
                                    sys.exit(1)
                            else:
                                print(f"\t\tCategory '{b}' is invalid and will be skipped (check the spelling)")
                    if block != "": block = "<block>" + block + "</block>"

                    cont = ""
                    if "continue" in profile:
                        for c in profile['continue']:
                            c = c.strip()
                            if c in current_url_categories:
                                cont = cont + "<member>" + c + "</member>"
                                if c in category_list_for_validation:
                                    category_list_for_validation.remove(c)
                                else:
                                    print(f"\t\tCategory '{c}' is specified more than once. Correct profile definition!")
                                    sys.exit(1)
                            else:
                                print(f"\t\tCategory '{c}' is invalid and will be skipped (check the spelling)")
                    if cont != "": cont = "<continue>" + cont + "</continue>"

                    override = ""
                    if "override" in profile:
                        for o in profile['override']:
                            o = o.strip()
                            if o in current_url_categories:
                                override = override + "<member>" + o + "</member>"
                                if o in category_list_for_validation:
                                    category_list_for_validation.remove(o)
                                else:
                                    print(f"t\t\tCategory '{o}' is specified more than once. Correct profile definition!")
                                    sys.exit(1)
                            else:
                                print(f"\t\tCategory '{o}' is invalid and will be skipped (check the spelling)")
                    if override != "": override = "<override>" + override + "</override>"

                    # Check if there are any categories left in the list - if so, they are not defined in the profile
                    if category_list_for_validation:
                        print(f"\t\tCategories {category_list_for_validation} do not have a defined [Action]")

                    # Categories per UCS (User Credential Submission) action
                    ucs = ""
                    if "credential-enforcement" in profile:

                        # We re-create a copy of categories to ensure each category is used only once for UCS
                        category_list_for_validation = current_url_categories.copy()

                        ucs_alert       = ""
                        ucs_allow       = ""
                        ucs_block       = ""
                        ucs_continue    = ""
                        ucs_mode        = ""
                        ucs_log_severity = ""

                        if "mode" in profile["credential-enforcement"]:
                            ucs_mode = f'<mode><{profile["credential-enforcement"]["mode"].strip().lower()}/></mode>'

                        if "log-severity" in profile["credential-enforcement"]:
                            ucs_log_severity = f'<log-severity>{profile["credential-enforcement"]["log-severity"].strip().lower()}</log-severity>'

                        if "alert" in profile["credential-enforcement"]:
                            for ua1 in profile["credential-enforcement"]["alert"]:
                                ua1 = ua1.strip()
                                if ua1 in current_url_categories:
                                    ucs_alert = ucs_alert + "<member>" + ua1 + "</member>"
                                    if ua1 in category_list_for_validation:
                                        category_list_for_validation.remove(ua1)
                                    else:
                                        print(f"t\t\tCategory '{ua1}' is specified more than once. Correct profile definition!")
                                        sys.exit(1)
                                else:
                                    print(f"\t\tCategory '{ua1}' is invalid and will be skipped (check the spelling)")
                        ucs_alert = "<alert>" + ucs_alert + "</alert>"

                        if "allow" in profile["credential-enforcement"]:
                            for ua2 in profile["credential-enforcement"]["allow"]:
                                ua2 = ua2.strip()
                                if ua2 in current_url_categories:
                                    ucs_allow = ucs_allow + "<member>" + ua2 + "</member>"
                                    if ua2 in category_list_for_validation:
                                        category_list_for_validation.remove(ua2)
                                    else:
                                        print(f"\t\tCategory '{ua2}' is specified more than once. Correct profile definition!")
                                        sys.exit(1)
                                else:
                                    print(f"\t\tCategory '{ua2}' is invalid and will be skipped (check the spelling)")
                        ucs_allow = "<allow>" + ucs_allow + "</allow>"

                        if "block" in profile["credential-enforcement"]:
                            for ub in profile["credential-enforcement"]["block"]:
                                ub = ub.strip()
                                if ub in current_url_categories:
                                    ucs_block = ucs_block + "<member>" + ub + "</member>"
                                    if ub in category_list_for_validation:
                                        category_list_for_validation.remove(ub)
                                    else:
                                        print(f"\t\tCategory '{ub}' is specified more than once. Correct profile definition!")
                                        sys.exit(1)
                                else:
                                    print(f"\t\tCategory '{ub}' is invalid and will be skipped (check the spelling)")
                        ucs_block = "<block>" + ucs_block + "</block>"

                        if "continue" in profile["credential-enforcement"]:
                            for uc in profile["credential-enforcement"]["continue"]:
                                uc = uc.strip()
                                if uc in current_url_categories:
                                    ucs_continue = ucs_continue + "<member>" + uc + "</member>"
                                    if uc in category_list_for_validation:
                                        category_list_for_validation.remove(uc)
                                    else:
                                        print(f"\t\t\t\tCategory '{uc}' is specified more than once. Correct profile definition!")
                                        sys.exit(1)
                                else:
                                    print(f"\t\tCategory '{uc}' is invalid and will be skipped (check the spelling)")
                        ucs_continue = "<continue>" + ucs_continue + "</continue>"

                        ucs = '<credential-enforcement>' + ucs_mode + ucs_log_severity + ucs_alert + ucs_allow + ucs_block + ucs_continue + '</credential-enforcement>'

                        # Check if there are any categories left in the list - if so, they are not defined in the profile
                        if category_list_for_validation:
                            print(f"\t\tCategories {category_list_for_validation} do not have a defined [User Credential Submission Action]")

                    # Now we get description, log settings and safe search enforcement
                    description = ""
                    if "description" in profile:
                        description = "<description>" + profile['description'] + "</description>"
                    # =====================================================================================
                    log_container_page_only = ""
                    if "log-container-page-only" in profile:
                        log_container_page_only = "<log-container-page-only>" + profile['log-container-page-only'].lower() + "</log-container-page-only>"
                    # =====================================================================================
                    log_http_hdr_referer = ""
                    if "log-http-hdr-referer" in profile:
                        log_http_hdr_referer = "<log-http-hdr-referer>" + profile['log-http-hdr-referer'].lower() + "</log-http-hdr-referer>"
                    # -------------------------------------------------------------------------------------
                    log_http_hdr_user_agent = ""
                    if "log-http-hdr-user-agent" in profile:
                        log_http_hdr_user_agent = "<log-http-hdr-user-agent>" + profile['log-http-hdr-user-agent'].lower() + "</log-http-hdr-user-agent>"
                    # -------------------------------------------------------------------------------------
                    log_http_hdr_xff = ""
                    if "log-http-hdr-xff" in profile:
                        log_http_hdr_xff = "<log-http-hdr-xff>" + profile['log-http-hdr-xff'].lower() + "</log-http-hdr-xff>"
                    # =====================================================================================
                    safe_search_enforcement = ""
                    if "safe-search-enforcement" in profile:
                        safe_search_enforcement = "<safe-search-enforcement>" + profile['safe-search-enforcement'].lower() + "</safe-search-enforcement>"
                    # =====================================================================================
                    dis_override = ""
                    if "disable override" in profile and isinstance(panos_device, Panorama):  # only Panorama supports the 'disable override' option
                        dis_override = "<disable-override>" + profile['disable override'] + "</disable-override>"

                    # Finally, we construct the complete Element part of the multi-config sub-operation
                    obj_element = (alert + allow + block + cont + override + ucs + description + dis_override
                                   + log_container_page_only + log_http_hdr_referer + log_http_hdr_user_agent
                                   + log_http_hdr_xff + safe_search_enforcement)

                    # check to see if the example profile needs to be created and skip to the next iteration
                    # (without actual creation) if not
                    if settings.CREATE_EXAMPLE_SECURITY_PROFILES is False and "example" in profile['name'].lower():
                        continue
                    else:
                        # here we finalize the definition of the sub-operation (the whole profile if defined here)
                        print(f"\tStaging profile: {profile['name']}")

                        multi_config_xml += f'<set id="{action_id}" xpath="{obj_xpath}">{obj_element}</set>'
                        action_id += 1
                else:
                    print(f"Profile data failed to be read from '{file_name}'")

    # finalize the multi-config XML and execute the creation
    multi_config_xml += '</multi-config>'
    execute_multi_config_api_call(panos_device, multi_config_xml, "Creating all staged static URL-filtering profiles...", 0)


def create_url_filtering_auto_profiles(profile_container, url_categories, current_url_categories, panos_device):
    """
    Creates URL filtering profiles automatically based on specified managed URL categories and applies
    them to the Palo Alto Networks device via API calls. This function ensures that each URL category
    is uniquely mapped to appropriate actions based on its specifications, and validates the input data
    for consistency and correctness.

    Args:
        profile_container: Device Group or VSYS object where the profiles will be created.
        url_categories: List of dictionaries containing details about URL categories and their
            associated actions. Each dictionary is expected to include 'Category' and
            'Action' keys.
        current_url_categories: List of currently active URL categories, used for validation
            to prevent duplicate processing or invalid categories.
        panos_device: Firewall or Panorama device object.
    """
    print("Staging dynamic URL-filtering profiles:")
    panos_device.add(profile_container)
    # first, we initialize the multi-config XML code
    multi_config_xml = '<multi-config>'

    # 2. build profiles - auto-generated from managed URL categories
    alert = ""
    allow = ""
    block = ""
    cont = ""
    override = ""

    # First, we construct the XPATH components of the auto-generated profiles
    obj_xpath1 = profile_container.xpath() + "/profiles/url-filtering/entry[@name='" + settings.SP_URL_NON_CTRLD + "']"
    obj_xpath2 = profile_container.xpath() + "/profiles/url-filtering/entry[@name='" + settings.SP_URL_NON_CTRLD_RISKY + "']"

    # now we construct the "element" defining details of the objects referenced by the XPATH

    # We create a copy of current categories to ensure each category is used only once
    category_list_for_validation = current_url_categories.copy()

    # in this loop we're going through all categories and their actions, populating
    # relevant XML lists for each action type: alert/block/override/continue
    for category in url_categories:
        action         = category['Action'].lower().strip()
        category_name  = category['Category'].strip()  # we do not need to normalize case with lower() here
                                                       # because the current_url_categories received from the device
                                                       # may contain upper-case symbols (such as "AI-code-assistant")
        if category_name in current_url_categories:
            if category_name in category_list_for_validation:
                category_list_for_validation.remove(category_name)
                if action == settings.url_action_alert:
                    alert = alert + "<member>" + category_name + "</member>"
                elif action == settings.URL_ACTION_MANAGE or action == settings.URL_ACTION_DENY:
                    block = block + "<member>" + category_name + "</member>"
                elif action == settings.URL_ACTION_CONTINUE:
                    cont  = cont + "<member>" + category_name + "</member>"
                elif action == settings.URL_ACTION_ALLOW:
                    allow = allow + "<member>" + category_name + "</member>"
                elif action == settings.URL_ACTION_OVERRIDE:
                    override = override + "<member>" + category_name + "</member>"
                else:
                    print(f"ERROR: category [{category_name}] is specified with invalid action [{action}]."
                          f"\nValid actions are: [{settings.URL_ACTION_MANAGE}], [{settings.url_action_alert}], [{settings.URL_ACTION_DENY}], [{settings.URL_ACTION_CONTINUE}], [{settings.URL_ACTION_ALLOW}]. "
                          f"\nCorrect the mistake in the file [{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}] and re-run the script."
                          f"\n")
                    sys.exit(1)
            else:
                print(f"ERROR: category [{category_name}] is specified more than once. Correct this name in the file [{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}] and re-run the script.")
                sys.exit(1)
        else:
            print(f"ERROR: category name [{category_name}] is invalid. Correct this name in the file [{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}] and re-run the script.")
            sys.exit(1)

    alert = "<alert>" + alert + "</alert>"
    block = "<block>" + block + "</block>"
    cont = "<continue>" + cont + "</continue>"
    allow = "<allow>" + allow + "</allow>"
    override = "<override>" + override + "</override>"

    # UCS action is hard-coded to be identical to the main action (with the exception of Override)
    ucs_mode1         = "ip-user"
    ucs_log_severity1 = "informational"

    ucs1 = f'<credential-enforcement><mode><{ucs_mode1}/></mode><log-severity>{ucs_log_severity1}</log-severity>{alert}{block}{allow}{cont}</credential-enforcement>'

    ucs_mode2         = "ip-user"
    ucs_log_severity2 = "low"

    ucs2 = f'<credential-enforcement><mode><{ucs_mode2}/></mode><log-severity>{ucs_log_severity2}</log-severity>{alert}{block}{allow}{cont}</credential-enforcement>'

    description1 = "URL filtering profile for policy rules with controlled categories (where categories are " \
                   "NOT specified as a matching criterion - hence the blocking actions in the profile). This" \
                   "profile has been autogenerated."

    description2 = "URL filtering profile for policy rules with controlled categories with Medium and High " \
                   "risk  (where categories are NOT specified as a matching criterion - hence the blocking " \
                   "actions in the profile). This profile has been autogenerated."

    obj_element1 = alert + allow + block + cont + override + "<description>" + description1 + "</description>" \
                   + "<log-container-page-only>" + "yes" + "</log-container-page-only>" \
                   + "<log-http-hdr-referer>"    + "no" + "</log-http-hdr-referer>" \
                   + "<log-http-hdr-user-agent>" + "yes" + "</log-http-hdr-user-agent>" \
                   + "<log-http-hdr-xff>"        + "no" + "</log-http-hdr-xff>" \
                   + "<safe-search-enforcement>" + "no" + "</safe-search-enforcement>" \
                   + ucs1

    obj_element2 = alert + allow + block + cont + override + "<description>" + description2 + "</description>" \
                   + "<log-container-page-only>" + "no" + "</log-container-page-only>" \
                   + "<log-http-hdr-referer>"    + "yes" + "</log-http-hdr-referer>" \
                   + "<log-http-hdr-user-agent>" + "yes" + "</log-http-hdr-user-agent>" \
                   + "<log-http-hdr-xff>"        + "yes" + "</log-http-hdr-xff>" \
                   + "<safe-search-enforcement>" + "no" + "</safe-search-enforcement>" \
                   + ucs2

    # here we finalize the definition of the sub-operation (the whole profile if defined here)
    print(f"\t{settings.SP_URL_NON_CTRLD} (auto-generated based on requirements)")
    print(f"\t{settings.SP_URL_NON_CTRLD_RISKY} (auto-generated based on requirements)")

    multi_config_xml += f'<set id="1" xpath="{obj_xpath1}">{obj_element1}</set>'
    multi_config_xml += f'<set id="2" xpath="{obj_xpath2}">{obj_element2}</set>'

    # finalize the multi-config XML and execute the deletion
    multi_config_xml += '</multi-config>'
    execute_multi_config_api_call(panos_device, multi_config_xml,"Creating all auto-generated URL-filtering profiles...", 0)
