"""
Functions for creating and managing application filters in PAN-OS.

This module provides functionality to create application filters based on
business requirements for managed and non-managed application categories.
It handles filtering applications by subcategory, category, tags, and risk
levels, and supports excluding specific applications from filters.
"""

from panos.objects import ApplicationFilter
from ngfw.objects.tags.tags import tags
from lib.auxiliary_functions import execute_multi_config_api_call
import settings
from rich import print
from rich.console import Console
from rich.table import Table


def create_application_filters(target, panos_device, app_categories):
    """
    Stages application filters based on the business requirements for
    managed and non-managed application categories. This function processes
    each application category, determines the appropriate action according
    to the specified settings, and stages application filters accordingly.
    It generates and returns Multi-Config Element XML for all staged
    application filters, including handling excluded applications for certain
    subcategories.

    Args:
        panos_device: Firewall or Panorama device object.
        target: Device Group or VSYS object where the application filters will be created
        app_categories: List of application category dictionaries. Each
            dictionary specifies 'Action', 'SubCategory', 'Category', 'Tags',
            'Risk', and 'ExcludedApps' associated with the application
            category. The 'Action' field defines how to handle the category,
            such as manage, do not manage (alert), or deny.

    Returns:
        str: A Multi-Config Element XML string representing all the staged
        application filters.
    """
    panos_device.add(target)
    # ===========================================================================================
    # Creation of Application Filters that need to be either managed or non-managed (yet allowed)
    console = Console()
    console.print("Staging application filters for managed and non-managed app categories:")

    # Create a table for application categories
    table = Table(title="Application Filters for Categories")
    table.add_column("SubCategory", style="cyan")
    table.add_column("Action", style="magenta")
    table.add_column("Filter Name", style="green")
    table.add_column("Status", style="yellow")

    managed_categories = []
    categories_with_excluded_apps = {}
    for category in app_categories:
        if category["Action"].lower() == settings.APP_ACTION_ALERT:
            managed_categories.append(category["Category"].lower())

        if category["Action"].lower() == settings.APP_ACTION_MANAGE or category["Action"].lower() == settings.APP_ACTION_ALERT:

            apf_subcategory = category["SubCategory"].lower()
            apf_name        = settings.PREFIX_FOR_APPLICATION_FILTERS + apf_subcategory
            apf_name_all    = settings.PREFIX_FOR_APPLICATION_FILTERS + apf_subcategory + '-all'

            list_of_categories = category["Category"].lower().split(',')
            list_of_categories = [x.strip(' ') for x in list_of_categories]
            apf_category = None if list_of_categories == [''] else list_of_categories

            list_of_tags = category["Tags"].split(',')
            list_of_tags = [x.strip(' ') for x in list_of_tags]
            apf_tags = None if list_of_tags == [''] else list_of_tags

            list_of_risks = category["Risk"].split(',')
            list_of_risks = [x.strip(' ') for x in list_of_risks]
            apf_risks = None if list_of_risks == [''] else list_of_risks

            list_of_excluded = category["ExcludedApps"].split(',')
            list_of_excluded = [x.strip(' ') for x in list_of_excluded]
            apf_excluded = None if list_of_excluded == [''] else list_of_excluded

            # if there are any excluded apps for this subcategory
            # then we take a note of them in a special dictionary
            if apf_excluded:
                categories_with_excluded_apps.update({apf_name: apf_excluded})

            # Stage the custom application filter
            target.add(ApplicationFilter(name=apf_name,
                                         subcategory=apf_subcategory,
                                         category=apf_category,
                                         tag=apf_tags,
                                         risk=apf_risks))

            # Stage a generic application filter
            target.add(ApplicationFilter(name=apf_name_all, subcategory=apf_subcategory))

            table.add_row(
                category["SubCategory"],
                category["Action"].upper(),
                apf_name,
                "Staged (used for access control)"
            )

            table.add_row(
                category["SubCategory"],
                category["Action"].upper(),
                apf_name_all,
                "Staged (used to block non-sanctioned apps)"
            )

        elif category["Action"].lower() == settings.APP_ACTION_DENY:
            table.add_row(
                category["SubCategory"],
                category["Action"].upper(),
                "N/A",
                "Filter not required (blocked category)"
            )
        else:
            table.add_row(
                category["SubCategory"],
                category["Action"],
                "N/A",
                "Unknown value in Action field - skipping filter creation"
            )

    # Display the table
    console.print(table)

    # print("\t\tApplication filters - filter for globally sanctioned managed and unmanaged apps")
    # target_dg.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}sanctioned-managed-apps',
    #                                 subcategory=managed_categories, tag=['{tags["sanctioned-apps"]["name"]}'])).apply()

    # Create a table for risk-based filters
    risk_table = Table(title="Risk-Based Application Filters")
    risk_table.add_column("Filter Name", style="green")
    risk_table.add_column("Risk Level", style="red")
    risk_table.add_column("Status", style="yellow")

    # Add risk-based filters (effectively, they will cover applications from blocked categories)
    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-high-risk', risk=['5']))
    risk_table.add_row(f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-high-risk', '5 (Very High)', 'Staged')

    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}high-risk', risk=['4']))
    risk_table.add_row(f'{settings.PREFIX_FOR_APPLICATION_FILTERS}high-risk', '4 (High)', 'Staged')

    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}medium-risk', risk=['3']))
    risk_table.add_row(f'{settings.PREFIX_FOR_APPLICATION_FILTERS}medium-risk', '3 (Medium)', 'Staged')

    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}low-risk', risk=['2']))
    risk_table.add_row(f'{settings.PREFIX_FOR_APPLICATION_FILTERS}low-risk', '2 (Low)', 'Staged')

    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-low-risk', risk=['1']))
    risk_table.add_row(f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-low-risk', '1 (Very Low)', 'Staged')

    # Display the risk table
    console.print(risk_table)

    # Create a table for legacy custom apps
    legacy_table = Table(title="Legacy Custom Applications Filter")
    legacy_table.add_column("Filter Name", style="green")
    legacy_table.add_column("Tag", style="blue")
    legacy_table.add_column("Status", style="yellow")

    # Add legacy custom apps filter
    target.add(ApplicationFilter(name=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}custom-apps-legacy',
                                 tag=[f'{tags["legacy-custom-apps"]["name"]}']))
    legacy_table.add_row(
        f'{settings.PREFIX_FOR_APPLICATION_FILTERS}custom-apps-legacy',
        tags["legacy-custom-apps"]["name"],
        'Staged'
    )

    # Display the legacy table
    console.print(legacy_table)

    # Now we create Multi-Config Element XML for all staged app filters
    action_id = 1
    multi_config_xml = '<multi-config>'
    for app_filter in target.findall(ApplicationFilter):
        if "None" not in app_filter.xpath():
            # If the category had excluded apps then we add XML code for this
            if app_filter.name in categories_with_excluded_apps.keys():
                excluded_apps_xml = "<exclude>" + "".join(f"<member>{app}</member>" for app in categories_with_excluded_apps[app_filter.name]) + "</exclude></entry>"
                element = app_filter.element_str().decode().replace("</entry>", excluded_apps_xml)
            else:
                element = app_filter.element_str().decode()
            multi_config_xml += f'<edit id="{action_id}" xpath="{app_filter.xpath()}">{element}</edit>'
            action_id += 1
    multi_config_xml += '</multi-config>'

    # Finally, we execute the Multi-Config API call thus creating all app filters in one go
    execute_multi_config_api_call(panos_device, multi_config_xml, "Creating the staged application filters...", 0)
