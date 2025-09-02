"""
Functions for creating and managing tags in PAN-OS.

This module provides functionality to:

- Create and configure tags with specific colors and descriptions
- Handle both regular tags and group tags
- Apply tags to applications based on configuration files
- Deploy tags to PAN-OS devices using multi-config API calls
- Ensure no duplicate tags exist in the configuration
"""

import sys
import settings

from lib.auxiliary_functions         import execute_multi_config_api_call, parse_metadata_from_json
from ngfw.objects.tags.tags         import tags
from ngfw.objects.tags.group_tags   import group_tags
from panos.objects                  import Tag, ApplicationTag
from rich import print


def create_tags(tag_container, panos_device):
    """
    Adds tags to the configuration tree in the specified container.

    This function first refreshes the tags in the configuration tree to ensure
    no duplicate tags exist. Then it adds group tags and other tags respectively
    to the specified tag container. It performs these operations by creating a
    multi-config request and executing it.

    Args:
        tag_container: The container where tags will be added.
        panorama: Optional parameter for specifying the panorama to use for executing the multi-config request.
    """

    # Refresh current tags in the configuration tree
    # this should remove all tags from there provided the remove_tags() function
    # was executed before this function and deleted all tags from the target container
    Tag.refreshall(tag_container)

    # Now we loop through all group tags adding them to the container
    # as we do so we also populate element for a multi-config request
    if len(group_tags) != 0:
        action_id = 1
        multi_config_xml = '<multi-config>'
        for tag_item, tag_info in group_tags.items():
            tag_object=Tag(name=tag_info['name'], comments=tag_info['description'], color=Tag.color_code(tag_info['color']))
            tag_container.add(tag_object)
            multi_config_xml += f'<edit id="{action_id}" xpath="{tag_object.xpath()}">{tag_object.element_str().decode()}</edit>'
            action_id += 1
        multi_config_xml += '</multi-config>'
        # now we execute the constructed multi-config request
        execute_multi_config_api_call(panos_device, multi_config_xml, f'Creating group tags ({len(group_tags)} entries)...', 0)

    # Now we loop through all other tags adding them to the container
    # as we do so we also populate element for a multi-config request
    if len(tags) != 0:
        action_id = 1
        multi_config_xml = '<multi-config>'
        for tag_item, tag_info in tags.items():
            # # We add tag only if it's not already there
            if tag_container.find(tag_info['name'], Tag) is None:
                tag_object=Tag(name=tag_info['name'], comments=tag_info['description'], color=Tag.color_code(tag_info['color']))
                tag_container.add(tag_object)
                multi_config_xml += f'<edit id="{action_id}" xpath="{tag_object.xpath()}">{tag_object.element_str().decode()}</edit>'
                action_id += 1
        multi_config_xml += '</multi-config>'
        execute_multi_config_api_call(panos_device, multi_config_xml, f'Creating/updating other tags ({len(tags)} entries)...', 0)


def tag_applications(tag_container, panos_device):
    print("Staging application signature tagging...")
    metadata = parse_metadata_from_json("List of tagged applications", settings.TAGGED_APPLICATIONS_FILENAME, True)
    # now we build a dictionary {"<app>": [<app tags>]}
    applications = {}
    if metadata:
        for tag in metadata:
            tag_name            = tag['tag_name']
            tagged_applications = tag['tagged_applications']

            for app in tagged_applications:
                if app not in applications:
                    applications[app] = []
                applications[app].append(tag_name)

    # now we create ApplicationTag objects, add them to the target, and grab their XML representation for the multi-config
    action_id = 1
    multi_config_xml = '<multi-config>'
    for app, tags in applications.items():
        tagged_app = ApplicationTag(app, tags)
        tag_container.add(tagged_app)
        multi_config_xml += f'<edit id="{action_id}" xpath="{tagged_app.xpath()}">{tagged_app.element_str().decode()}</edit>'
        action_id += 1
    multi_config_xml += '</multi-config>'

    execute_multi_config_api_call(panos_device, multi_config_xml, "Tagging the staged applications...", 0)
