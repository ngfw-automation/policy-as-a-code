"""
Functions for creating and managing application groups in PAN-OS.

This module provides functionality to create application groups based on
application categories defined in business requirements. It handles both
managed and non-managed application categories, creating appropriate
application groups for each category and a special group for all
non-managed applications.
"""

import sys
from panos.objects import ApplicationGroup
from lib.auxiliary_functions import parse_metadata_from_json
from lib.auxiliary_functions import execute_multi_config_api_call
import settings
from rich import print


def create_application_groups(target, panos_device, app_categories):
    # Creation of Application Filters that need to be either managed or non-managed (yet allowed)
    print(f'Staging application groups for managed and non-managed app categories to account for optional '
          f'extra apps...', end='')
    for category in app_categories:
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE or
                category["Action"].lower() == settings.APP_ACTION_ALERT):
            apps = list()
            if category["ExtraApps"] != '':
                apps = category["ExtraApps"].split(',')
            app_filter = settings.PREFIX_FOR_APPLICATION_FILTERS + category["SubCategory"].lower()
            members = [app_filter]
            if len(apps) > 0:  # if the list of apps is not empty - strip spaces from all entries
                for i, s in enumerate(apps):
                    apps[i] = s.strip()
            members.extend(apps)  # add the list of apps to the application filter for them all to become application group members
            target.add(ApplicationGroup(name='APG-' + category["SubCategory"].lower(), value=members))

    # Group for all non-managed apps
    groups_for_non_managed_cats = list()
    for category in app_categories:
        if category["Action"].lower() == settings.APP_ACTION_ALERT:
            groups_for_non_managed_cats.append("APG-"+category["SubCategory"].lower())
    target.add(ApplicationGroup(name='APG-non-managed-apps', value=groups_for_non_managed_cats))
    print('done')

    # Read the application groups from the JSON file
    metadata = parse_metadata_from_json("Application Groups", settings.APPLICATION_GROUPS_FILENAME)

    # Check if metadata was successfully read
    if metadata:
        for app_group in metadata:
            target.add(ApplicationGroup(name=app_group['name'], value=app_group['value']))
    else:
        print("No application groups were added due to missing or invalid metadata.")
        sys.exit(1)

    # Now we create Multi-Config Element XML for all staged app groups
    action_id = 1
    multi_config_xml = '<multi-config>'
    for app_group in target.findall(ApplicationGroup):
        if "None" not in app_group.xpath():
            multi_config_xml += f'<edit id="{action_id}" xpath="{app_group.xpath()}">{app_group.element_str().decode()}</edit>'
            action_id += 1
    multi_config_xml += '</multi-config>'

    execute_multi_config_api_call(panos_device, multi_config_xml, "Creating the staged application groups...", 0)
