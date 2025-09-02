"""
Functions providing auxiliary utilities for PAN-OS policy management.

This module provides a collection of helper functions used throughout the project for:

- Parsing metadata from JSON and CSV files
- Finding differences between address objects and groups
- Executing multi-config API calls to PAN-OS devices
- Creating non-SDK objects in PAN-OS
- Handling file operations and error handling
- Supporting various data transformation and validation tasks
- Pluralizing words for consistent naming conventions
"""

import importlib
import os.path
import json
import csv
import sys
import re
import time
import xml.dom.minidom
from importlib import metadata as metadata

import yaml
from rich import print
from rich.panel import Panel
from rich.status import Status
from lib.rich_output import console

from xmltodict import unparse
from panos.errors   import PanDeviceXapiError
from panos.policies import SecurityRule, DecryptionRule, AuthenticationRule, NatRule
from panos.objects import Edl, ServiceObject, ServiceGroup, ApplicationGroup, ApplicationFilter, CustomUrlCategory, \
    LogForwardingProfile, Tag

from lib.category_parser    import parse_app_categories, parse_url_categories
import settings

# Global variables
menu_options = None
default_choice = None

# Module-level variable to track whether execute_multi_config_api_call has been called before
_first_multi_config_call = True


def get_source_user_for_category(category, category_type):
    """
    Fetches the source user associated with a given category and category type based on
    CSV files with business requirements. Only managed categories will be evaluated. In other
    words, you can use this function to retrieve UserID only for those categories that you decide to manage
    and declare as such in the business requirements CSV files.

    Args:
        category (str): The specific category to evaluate (e.g., subcategory for apps or
            a general category for URLs).
        category_type (str): The type of the category, which can be either "app" or "url".
            Determines what kind of category will be processed.

    Returns:
        Optional[str]: The user ID that corresponds to the specified category and
            category type. Returns None if no match is found.

    Raises:
        SystemExit: If the provided category type is invalid.
    """
    source_user = None
    if category_type.lower() == "app":
        app_categories_requirements = parse_app_categories(settings.APP_CATEGORIES_REQUIREMENTS_FILENAME)
        for entry in app_categories_requirements:
            if category == entry["SubCategory"] and entry["Action"] == settings.APP_ACTION_MANAGE:
                source_user = entry["UserID"]
                break
    elif category_type.lower() == "url":
        url_categories_requirements = parse_url_categories(settings.URL_CATEGORIES_REQUIREMENTS_FILENAME)
        for entry in url_categories_requirements:
            if category == entry["Category"] and entry["Action"] == settings.URL_ACTION_MANAGE:
                source_user = entry["UserID"]
                break
    else:
        print(f"Invalid category type: {category_type}")
        sys.exit(1)

    return source_user


def parse_metadata_from_json(type_display_name, file_name, suppress_output=True):
    """
    Parses metadata from a JSON file.

    Args:
        type_display_name (str): A display name for the type of metadata being parsed.
        file_name (str): The path to the JSON file containing the metadata.
        suppress_output (bool): If True, suppresses output messages. Defaults to True.

    Returns:
        dict or None: The parsed metadata as a dictionary, or None if the file does not exist or cannot be parsed.
    """
    metadata = None
    if os.path.exists(file_name) and os.path.isfile(file_name):
        if not suppress_output: print(f"\t\tMetadata type :: " + type_display_name.upper() + " :: file is found - parsing data...", end='')
        # reading the file into a dictionary
        try:
            with open(file_name, mode='r', encoding='utf-8-sig') as json_file:
                 metadata = json.load(json_file)
            if not suppress_output: print(f'{len(metadata)} entries found.')
        # handle exceptions
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)
        except FileNotFoundError:
            print("The file was not found.")
        except ValueError or IOError:
            print("Failed to open the file (check if it's open in another program)")
    else:
        print(f"\t\tMetadata type :: " + type_display_name.upper() + " :: no files found")

    return metadata


def parse_metadata_from_yaml(type_display_name, file_name, suppress_output=True):
    """
    Parses metadata from a YAML file.

    Args:
        type_display_name (str): A display name for the type of metadata being parsed.
        file_name (str): The path to the YAML file containing the metadata.
        suppress_output (bool): If True, suppresses output messages. Defaults to True.

    Returns:
        dict or None: The parsed metadata as a dictionary, or None if the file does not exist or cannot be parsed.
    """
    metadata = None
    if os.path.exists(file_name) and os.path.isfile(file_name):
        if not suppress_output: print(f"\t\tMetadata type :: " + type_display_name.upper() + " :: file is found - parsing data...", end='')
        # reading the file into a dictionary
        try:
            with open(file_name, mode='r', encoding='utf-8-sig') as yaml_file:
                 metadata = yaml.safe_load(yaml_file)
            if not suppress_output: print(f'{len(metadata)} entries found.')
        # handle exceptions
        except yaml.YAMLError as e:
            print("Invalid YAML syntax:", e)
        except FileNotFoundError:
            print("The file was not found.")
        except ValueError or IOError:
            print("Failed to open the file (check if it's open in another program)")
    else:
        print(f"\t\tMetadata type :: " + type_display_name.upper() + " :: no files found")

    return metadata


def parse_metadata_from_csv(type_display_name, file_name, suppress_output=True):
    """
    Reads a CSV file with metadata of a profile/object of a given type.

    Read data is stored in a list of dictionaries (one dictionary per row
    with column names used as dictionary keys).

    Args:
        type_display_name (str): Type of the object ("EDL", "vulnerability", "antivirus", etc.)
        file_name (str): Path to the CSV file containing metadata.
        suppress_output (bool, optional): If True, suppresses output messages. Defaults to True.

    Returns:
        list or None: A list of dictionaries containing the values read from the CSV.
            Returns None if the file does not exist.
    """
    if os.path.exists(file_name):
        if not suppress_output: print(f"\t\tMetadata type :: " + type_display_name.upper() + f" :: parsing [{file_name}]...", end='')
        # reading the file into a list of dictionaries
        metadata = list()
        with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                metadata.append(row)
        if not suppress_output: print(f'{len(metadata)} entries found.')
    else:
        print(f"\t\tMetadata type :: " + type_display_name.upper() + " :: no files found")
        metadata = None

    return metadata


def find_address_objects_delta(current_address_objects, staged_address_objects):
    def make_hashable(value):
        if isinstance(value, list):
            return tuple(value)  # Convert list to tuple
        if isinstance(value, dict):
            return frozenset(value.items())  # Convert dict to frozenset
        return value  # Keep it as-is if it's already hashable

    def to_comparable_set(objects):
        return set(
            (
                make_hashable(obj.name),
                make_hashable(obj.type),
                make_hashable(obj.value),
                make_hashable(sorted(obj.tag) if obj.tag is not None else []),
                make_hashable(obj.description),
            ) for obj in objects
        )

    # Generate comparable sets
    current_set = to_comparable_set(current_address_objects)
    staged_set  = to_comparable_set(staged_address_objects)

    # Calculate deltas
    in_current_not_in_staged = current_set - staged_set
    in_staged_not_in_current = staged_set - current_set

    # Convert deltas back to original objects
    delta_current = [
        obj for obj in current_address_objects
        if (
            make_hashable(obj.name),
            make_hashable(obj.type),
            make_hashable(obj.value),
            make_hashable(sorted(obj.tag) if obj.tag is not None else []),
            make_hashable(obj.description),
        ) in in_current_not_in_staged
    ]

    delta_staged = [
        obj for obj in staged_address_objects
        if (
            make_hashable(obj.name),
            make_hashable(obj.type),
            make_hashable(obj.value),
            make_hashable(sorted(obj.tag) if obj.tag is not None else []),
            make_hashable(obj.description),
        ) in in_staged_not_in_current
    ]

    return delta_current, delta_staged


def find_address_groups_delta(current_address_groups, staged_address_groups):
    def make_hashable(value):
        if isinstance(value, list):
            return tuple(value)  # Convert list to tuple
        if isinstance(value, dict):
            return frozenset(value.items())  # Convert dict to frozenset
        return value  # Keep it as-is if it's already hashable

    def to_comparable_set(objects):
        return set(
            (
                make_hashable(obj.name),
                make_hashable(obj.description if obj.description not in ("", None) else None),
                make_hashable(sorted(obj.static_value) if obj.static_value is not None else []),
                make_hashable(sorted(obj.dynamic_value) if obj.dynamic_value is not None else []),
                make_hashable(sorted(obj.tag) if obj.tag is not None else [])
            ) for obj in objects
        )

    # Generate comparable sets
    current_set = to_comparable_set(current_address_groups)
    staged_set = to_comparable_set(staged_address_groups)

    # Calculate deltas
    in_current_not_in_staged = current_set - staged_set
    in_staged_not_in_current = staged_set - current_set

    # Convert deltas back to original objects
    delta_current = [
        obj for obj in current_address_groups
        if (
            make_hashable(obj.name),
            make_hashable(obj.description if obj.description not in ("", None) else None),
            make_hashable(sorted(obj.static_value) if obj.static_value is not None else []),
            make_hashable(sorted(obj.dynamic_value) if obj.dynamic_value is not None else []),
            make_hashable(sorted(obj.tag) if obj.tag is not None else [])
        ) in in_current_not_in_staged
    ]

    delta_staged = [
        obj for obj in staged_address_groups
        if (
            make_hashable(obj.name),
            make_hashable(obj.description if obj.description not in ("", None) else None),
            make_hashable(sorted(obj.static_value) if obj.static_value is not None else []),
            make_hashable(sorted(obj.dynamic_value) if obj.dynamic_value is not None else []),
            make_hashable(sorted(obj.tag) if obj.tag is not None else [])
        ) in in_staged_not_in_current
    ]

    return delta_current, delta_staged


def delete_objects(panos_device, objects_to_delete, failure_mode="hard", transactional=False):
    """
    Deletes specified objects on a PAN-OS device using a multi-config API call.

    This function constructs an XML request to delete multiple objects of the specified
    types on a PAN-OS device. It supports various object types and generates a human-readable
    name for the objects being deleted. The function also provides options to handle failures
    and execute the operation transactionally.

    Args:
        panos_device: The PAN-OS device on which the objects will be deleted.
        objects_to_delete: A list of objects to delete. Each object must have a `xpath` method
            that returns the XPath of the object on the device.
        failure_mode: Specifies how failures should be handled during the deletion process.
            Defaults to "hard".
        transactional: A boolean indicating whether the deletion should be executed transactionally.
            This means that when a commit operation is active or a commit is pending, the operation will fail.
            When there are uncommitted changes for the user performing the operation,
            they will be rolled back before performing the operation.
    """
    if objects_to_delete is not None and len(objects_to_delete) > 0:
        # Initialize a starting action ID (arbitrary number that increments for each element)
        action_id = 1
        # Construct multi-config XML
        multi_config_xml = '<multi-config>'
        for o in objects_to_delete:
            multi_config_xml += f'<delete id="{action_id}" xpath="{o.xpath()}"></delete>'
            action_id += 1
        multi_config_xml += '</multi-config>'

        # Map classes to their desired display strings
        mapping = {
            SecurityRule:           "security rule",
            DecryptionRule:         "decryption rule",
            NatRule:                "NAT rule",
            AuthenticationRule:     "authentication rule",
            Edl:                    "EDL",
            ServiceObject:          "service",
            ServiceGroup:           "service group",
            ApplicationGroup:       "application group",
            ApplicationFilter:      "application filter",
            CustomUrlCategory:      "custom URL category",
            LogForwardingProfile:   "log forwarding profile",
            Tag:                    "tag"
        }

        # Let's create a human-friendly name of the objects we're deleting
        cls = type(objects_to_delete[0])
        if cls not in mapping:
            print(f"Warning: Unmapped type '{cls.__name__}'. Falling back to default naming.")
            obj_name = cls.__name__.lower()
        else:
            obj_name = mapping.get(cls)

        # Let's go crazy and make the name plural if we have more than one object :)
        if len(objects_to_delete) > 1: obj_name=pluralize(obj_name)

        # Now we execute the multi-config request
        execute_multi_config_api_call(panos_device, multi_config_xml, f"Deleting {len(objects_to_delete)} {obj_name}...", 0, failure_mode, transactional)


def delete_non_sdk_objects(object_container, panos_device, objects_to_delete=()):
    """
    This function enumerates and deletes objects of specified types that do not have standard classes
    in the PAN-OS SDK for Python. It uses a preset dictionary to lookup XPATHs for each object type.

    Args:
        object_container (ObjectContainer): The container representing configuration
            components to retrieve their XPath.
        panos_device (PanOSDevice): The device object used to interact with PAN-OS
            firewalls or Panorama via API.
        objects_to_delete (tuple): A tuple containing the types of objects to delete, as
            defined in the `object_types` dictionary keys.

    Raises:
        Exception: If the deletion operation fails, or if objects fail to enumerate.
    """
    panos_device.add(object_container)
    print(f"Discovering and deleting objects prior to their (re)creation...")

    # As of Python version 3.7, dictionaries are ordered. In Python 3.6 and earlier, dictionaries are unordered.
    # therefore it's important to run this code with v3.7 or later as the profile groups must be deleted before
    # the profiles themselves

    object_types = {
        'profile-group': {
            'display_name': 'profile groups',
            'xpath':        'profile-group',
            'type':         'profile-group'
        },
        'vulnerability': {
            'display_name': 'vulnerability profiles',
            'xpath':        'profiles/vulnerability',
            'type':         'vulnerability'
        },
        'virus': {
            'display_name': 'antivirus profiles',
            'xpath':        'profiles/virus',
            'type':         'virus'
        },
        'spyware': {
            'display_name': 'anti-spyware profiles',
            'xpath':        'profiles/spyware',
            'type':         'spyware'
        },
        'wildfire-analysis': {
            'display_name': 'wildfire analysis profiles',
            'xpath':        'profiles/wildfire-analysis',
            'type':         'wildfire-analysis'
        },
        'file-blocking': {
            'display_name': 'file blocking profiles',
            'xpath':        'profiles/file-blocking',
            'type':         'file-blocking'
        },
        'data-filtering': {
            'display_name': 'data filtering profiles',
            'xpath':        'profiles/data-filtering',
            'type':         'data-filtering'
        },
        'data-objects': {
            'display_name': 'custom data patterns',
            'xpath':        'profiles/data-objects',
            'type':         'data-objects'
        },
        'url-filtering': {
            'display_name': 'URL filtering profiles',
            'xpath':        'profiles/url-filtering',
            'type':         'url-filtering'
        },
        'application-tag': {
            'display_name': 'tagged applications',
            'xpath':        'application-tag',
            'type':         'application-tag'
        },
        'application': {
            'display_name': 'custom application signatures',
            'xpath':        'application',
            'type':         'application'
        },
        'threat-vulnerability': {
            'display_name': 'custom vulnerability signatures',
            'xpath':        'threats/vulnerability',
            'type':         'vulnerability'
        },
        'threat-spyware': {
            'display_name': 'custom spyware signatures',
            'xpath':        'threats/spyware',
            'type':         'spyware'
        },
        'decryption': {
            'display_name': 'decryption profiles',
            'xpath': 'profiles/decryption',
            'type': 'decryption'
        }
    }

    action_id = 1
    multi_config_xml = '<multi-config>'

    for obj_key, obj_details in object_types.items():
        if obj_key in objects_to_delete:
            print(f"Enumerating {obj_details['display_name']}...", end="")

            xpath = object_container.xpath() + f"/{obj_details['xpath']}"
            profile_objects = panos_device.xapi.get(xpath)
            print(profile_objects.attrib['status'], end="")

            all_names = []
            if profile_objects.attrib['status'] == 'success':
                if settings.VERBOSE_OUTPUT: print(":")
                num_of_entries = 0
                for entries in profile_objects.findall(f".//{obj_details['type']}"):
                    for entry in entries.findall("entry"):
                        name = entry.get("name")
                        all_names.append(name)
                        num_of_entries += 1
                        if settings.VERBOSE_OUTPUT: print(f"\t{name}")
                if not settings.VERBOSE_OUTPUT: print(f" ({num_of_entries} entries found and staged for deletion)")
            else:
                print(" (failed to enumerate objects)")

            if all_names:
                for name in all_names:
                    obj_xpath = object_container.xpath() + f"/{obj_details['xpath']}/entry[@name='{name}']"
                    multi_config_xml += f'<delete id="{action_id}" xpath="{obj_xpath}"></delete>'
                    action_id += 1

    multi_config_xml += '</multi-config>'
    execute_multi_config_api_call(panos_device, multi_config_xml, "Deleting all staged objects...", 0)


def create_non_sdk_objects(object_container, panos_device, objects_to_create=()):
    """
    Creates non-SDK objects (such as security and decryption profiles) in a specified VSYS or Device Group
    of a firewall or Panorama. Objects must be pre-created in a JSON format in pre-configured folders
    defined in the Settings module. The function generates XML code for all required objects which is
    then applied to the target device using a multi-config API call.

    Args:
        object_container: Vsys or Device Group object where the objects will be created.

        panos_device: Firewall or Panorama object representing the target device.

        objects_to_create: An iterable containing keys representing the types of objects
            to create. Each key must match an available object type defined in `object_types`.
            Examples include 'vuln-profiles', 'av-profiles', 'spyware-profiles', etc. If invalid
            object types are included, a `ValueError` is raised.

    Raises:
        ValueError: If any of the specified `objects_to_create` are not present in the pre-defined
            `object_types`, the function raises an exception listing the invalid types.

    """
    object_types = {
        'vulnerability-profiles': {
            'display_name': 'vulnerability profiles',
            'xpath':        'profiles/vulnerability',
            'folder':       settings.SECURITY_PROFILES_VULNERABILITY_FOLDER,
        },
        'av-profiles': {
            'display_name': 'antivirus profiles',
            'xpath':        'profiles/virus',
            'folder':       settings.SECURITY_PROFILES_ANTIVIRUS_FOLDER,
        },
        'spyware-profiles': {
            'display_name': 'anti-spyware profiles',
            'xpath':        'profiles/spyware',
            'folder':       settings.SECURITY_PROFILES_ANTISPYWARE_FOLDER,
        },
        'wf-profiles': {
            'display_name': 'wildfire analysis profiles',
            'xpath':        'profiles/wildfire-analysis',
            'folder':       settings.SECURITY_PROFILES_WILDFIRE_FOLDER,
        },
        'file-profiles': {
            'display_name': 'file blocking profiles',
            'xpath':        'profiles/file-blocking',
            'folder':       settings.SECURITY_PROFILES_FILE_BLOCKING_FOLDER,
        },
        'data-patterns': {
            'display_name': 'custom data patterns',
            'xpath':        'profiles/data-objects',
            'folder':       settings.DATA_PATTERNS_FOLDER,
        },
        'data-profiles': {
            'display_name': 'data filtering profiles',
            'xpath':        'profiles/data-filtering',
            'folder':       settings.SECURITY_PROFILES_DATA_FILTERING_FOLDER,
        },
        'url-profiles': {
            'display_name': 'URL filtering profiles',
            'xpath':        'profiles/url-filtering',
            'folder':       settings.SECURITY_PROFILES_URL_FILTERING_FOLDER,
        },
        'decryption-profiles': {
            'display_name': 'decryption profiles',
            'xpath':        'profiles/decryption',
            'folder':       settings.DECRYPTION_PROFILES_FOLDER,
        }
    }

    # Validate objects_to_create
    invalid_objects = [obj for obj in objects_to_create if obj not in object_types]
    if invalid_objects:
        raise ValueError(f"Invalid object types specified: {invalid_objects}")

    # Output the names of the staged objects
    print("Staging objects for creation:", ", ".join(object_types[obj]['display_name'] for obj in objects_to_create))

    # Initialiase a counter and multi-config XML
    action_id = 1
    multi_config_xml = "<multi-config>"

    # Loop through all types of the objects that must be created
    for obj_type in objects_to_create:
        # Get object info
        obj_type_info = object_types[obj_type]
        # Get object's relative XPath (from the object info)
        obj_xpath     = object_container.xpath() + f"/{obj_type_info['xpath']}"

        # List all files in the given folder and analyze JSON and YAML files
        for file_name in os.listdir(obj_type_info['folder']):
            if file_name.endswith('.json') or file_name.endswith('.yaml'):  # Checks for .json or .yaml extension
                file_path = os.path.join(obj_type_info['folder'], file_name)
                if os.path.isfile(file_path):
                    # read data from the file (JSON or YAML)
                    if file_name.endswith('.json'):
                        object_definition = parse_metadata_from_json(obj_type_info['display_name'], file_path)
                    else:
                        object_definition = parse_metadata_from_yaml(obj_type_info['display_name'], file_path)
                    # now the 'object_definition' variable contains definition of the object in a form of a dictionary
                    if object_definition is not None:
                        print(f"\t{object_definition['entry']['@name']}")
                        # then we construct the element
                        if settings.DEBUG_OUTPUT:
                            # if DEBUG_OUTPUT is enabled we generate the element with pretty formatting
                            obj_element = unparse(object_definition, pretty=True, full_document=False)
                            # and output the object's definition to the console
                            print(f'Staged multi-config op #{action_id}:\n', obj_element)
                        else:
                            # if DEBUG_OUTPUT is not required, we generate the XML code in a condensed non-pretty form
                            obj_element = unparse(object_definition, pretty=False, full_document=False)
                        # we add the object definition to the multiconfig XML
                        multi_config_xml += f'<set id="{action_id}" xpath="{obj_xpath}">{obj_element}</set>'
                        # and increment the counter
                        action_id += 1
                    else:
                        # this is a "soft" error that would be displayed when the object definition
                        # has failed to be read from the JSON file
                        print(f"Profile data failed to be read from '{file_name}'")
            # Then we repeat the loop for the next file (= object definition) found in the folder
        # Then we repeat the loop for the next object type
    # Once we've finished with all object type we add a closing tag to the multi-config XML code
    multi_config_xml += '</multi-config>'
    # and execute the code (all objects will be created in one large multi_config API call)
    execute_multi_config_api_call(panos_device, multi_config_xml, f"Creating the staged objects...", 0)


def execute_multi_config_api_call(panos_device, multi_config_xml, output_message, indentation_level, failure_mode="hard", strict_transactional=False):
    """
    Executes a multi-configuration API call on a specified PAN-OS device.

    This function performs an API call to send a multi-configuration XML to a PAN-OS device.
    It manages the communication, logs the results, measures the execution time, and calculates
    average operation time if applicable. The function supports both strict and non-strict
    transactional modes.
    If an error occurs and the failure mode is set to `hard`, the
    program will terminate.

    Args:
        panos_device: The PAN-OS device object to which the API call will be sent.
        `multi_config_xml`: The XML string containing the multi-configuration data to apply.
        output_message: The base output message to display during execution.
        indentation_level: The indentation level for the output display, used to control
            formatting in the console.
        failure_mode: The failure mode behavior if an error occurs during execution.
            Options are `hard` (default) or other user-specified modes.
        strict_transactional: Flag to indicate whether to use strict transactional mode
            for applying the configuration.
            This means that when a commit operation is active or a commit is pending, the operation will fail.
            When there are uncommitted changes for the user performing the operation,
            they will be rolled back before performing the operation.
            Defaults to `False`.
            This parameter can be overridden by the global flag MAKE_THE_FIRST_MULTI_CONFIG_TRANSACTIONAL
            for the first call to always be True.
            This is the default behavior.
    """
    global _first_multi_config_call

    # Override strict_transactional for the first call
    if _first_multi_config_call and settings.MAKE_THE_FIRST_MULTI_CONFIG_TRANSACTIONAL:
        strict_transactional = True
        _first_multi_config_call = False

    # Log API calls if enabled
    if settings.LOG_API_CALLS:
        # Get current timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Determine file mode (overwrite or append)
        file_mode = "w" if strict_transactional else "a"

        # Log the API call to file
        with open(settings.API_CALLS_LOG_FILENAME, file_mode) as f:
            f.write(f"============== API Call at {timestamp} ====================\n")
            f.write(f"Strict Transactional:      {strict_transactional}\n")
            f.write(f"Associated output message: {output_message}\n")
            f.write("XML Content (formatted for readability):\n\n")
            # Pretty print the XML content
            try:
                # Parse the XML string and format it with proper indentation
                dom = xml.dom.minidom.parseString(multi_config_xml)
                pretty_xml = dom.toprettyxml(indent="  ")

                # Remove XML declaration line
                if pretty_xml.startswith('<?xml'):
                    pretty_xml = pretty_xml[pretty_xml.find('?>') + 2:].lstrip()

                # Remove empty lines
                pretty_xml = '\n'.join(line for line in pretty_xml.split('\n') if line.strip())

                f.write(pretty_xml)
            except Exception as e:
                # Fallback to original XML if parsing fails
                f.write(f"Error formatting XML: {str(e)}\n")
                f.write(multi_config_xml)
            f.write("\n\n")

    tabs = '\t' * indentation_level
    status_message = f"{tabs}{output_message}"
    if strict_transactional:
        status_message = f"{status_message} ([bold]strict transactional mode[/bold])"

    final_status_message = None

    with console.status(status_message, spinner="dots") as status_spinner:
        try:
            start_time = time.time()
            status = panos_device.xapi.multi_config(multi_config_xml, strict=strict_transactional)
            end_time = time.time()
            elapsed_time = end_time - start_time

            # Calculate elapsed time in seconds and milliseconds (without tenths)
            total_sec = int(elapsed_time)
            total_ms = int((elapsed_time - total_sec) * 1000)

            # Count number of operations (occurrences of " id=" in the XML)
            num_operations = multi_config_xml.count(" id=")
            if num_operations > 0:
                avg_time = elapsed_time / num_operations
                avg_sec = int(avg_time)
                avg_ms = int((avg_time - avg_sec) * 1000)
                avg_str = f"{avg_sec}s {avg_ms}ms"
            else:
                avg_str = "N/A"

            # Update the status with a green tick if successful
            result_message = f'{status.attrib["status"]} ({total_sec}s {total_ms}ms, {num_operations} ops, AVG: {avg_str} per op)'
            if status.attrib["status"] == "success":
                final_status_message = f"{status_message} [green]✓[/green] {result_message}"
            else:
                final_status_message = f"{status_message} [yellow]![/yellow] {result_message}"

            status_spinner.update(final_status_message)

            if settings.LOG_API_CALLS:
                # Get current timestamp
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

                # Log the API responses to file
                with open(settings.API_CALLS_LOG_FILENAME, "a") as f:
                    f.write(f"--- API Response at {timestamp} ---\n")
                    f.write(f"Result: {result_message}\n")
                    f.write("PAN-OS detailed response:\n\n")
                    # Output the result to the file
                    try:
                        for response in status.findall('.//response'):
                            resp_status = response.get('status')
                            code = response.get('code')
                            action_id = response.get('id')
                            msg = response.find('msg').text if response.find('msg') is not None else None
                            f.write(f"\tID: {action_id}, Status: {resp_status}, Code: {code}, Msg: {msg}\n")
                            if settings.DEBUG_OUTPUT:
                                console.print(f"{tabs}ID: {action_id}, Status: {resp_status}, Code: {code}, Msg: {msg}")
                        f.write(f"==================================================================\n\n\n\n")
                    except Exception as e:
                        console.print(f"Error writing the response to the file '{settings.API_CALLS_LOG_FILENAME}':")
                        console.print(f"{str(e)}\n")

        except PanDeviceXapiError as e:
            console.print('-- XML API error --')
            with open(settings.API_ERROR_LOG_FILENAME, "w") as f:
                f.write(str(e))
            console.print('-' * 80)
            console.print(e.message)
            console.print('-' * 80)
            console.print(f"If the message above appears truncated, review the log file [{settings.API_ERROR_LOG_FILENAME}] for the full error message.")
            if failure_mode == "hard":
                sys.exit(1)

    # Print the final status message after the context manager exits
    if final_status_message:
        console.print(final_status_message)


def load_module_from_file(module_name, file_path):
    """
    Loads a Python module from a specified file path using its module name.

    This function uses the importlib.util module to dynamically load a module
    by creating a module spec from the provided file path and then executing
    the module code within that spec. It then returns the loaded module object
    to the caller.

    Args:
        module_name: Name of the module as a string. This is the name under
            which the module will be available upon loading.
        file_path: Path to the module file as a string. This is the location on
            the filesystem from which the module will be loaded.

    Returns:
        The loaded module object, which can be used to access functions,
        classes, or variables defined in the module.
    """
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_and_import_rules(directory):
    """
    Finds and imports rule definitions from Python files within a given directory.

    This function searches through a directory structure, looking for files named
    `rules.py`. It attempts to import these files as modules, and if successful,
    it checks for the presence of `section_rules` and `section_defaults`
    attributes. When found, it merges each security rule with the default
    settings, ensuring the attributes set in the rule take priority over the default values.
    The function collects all the processed rules and their corresponding subfolder names for
    further use.

    Optionally, the function validates rule names and descriptions to ensure they comply
    with the naming convention set in the `settings` module.

    Args:
        directory (str): The root directory to search for 'rules.py' files.

    Returns:
        tuple: A tuple containing two elements:
            - A list of dictionaries, where each dictionary represents a security
              rule merged with default settings.
            - A list of strings, where each string is the name of the subfolder
              containing the corresponding rule file.
    """
    all_rules = []
    all_subfolder_names = []
    list_of_invalid_rules = []

    # Traverse the directory structure
    for root, dirs, files in os.walk(directory):
        # Sort directories and files to ensure a consistent processing order
        dirs.sort()
        files.sort()
        for file in files:
            if file == "rules.py":
                file_path = os.path.join(root, file)
                # Normalize the path to ensure consistency in slashes
                file_path = os.path.normpath(file_path).replace(os.sep, "/")
                # Create a unique module name based on the file path
                # first, we remove the file extension
                module_name = file_path.replace(".py", "")
                # second, we substitute all slashes, dots and spaces with the underscore
                module_name_normilized = re.sub(r"[ /.\\-]", "_", module_name)
                # finally, we Load the module from the normalized file path
                try:
                    module = load_module_from_file(module_name_normilized, file_path)
                except SyntaxError as e:
                    print(f"!!! Syntax error in rule definitions in the file: '{file_path}'")
                    print(e)
                    sys.exit(1)

                # Check if 'section_rules' and 'section_defaults' are present
                if hasattr(module, 'section_rules') and hasattr(module, 'section_defaults'):
                    # Merge defaults with each rule, ensuring not to overwrite existing keys
                    updated_rules = []
                    folder_name = os.path.basename(root)  # Get the subfolder name
                    for rule in module.section_rules:
                        # Start with a copy of the defaults
                        merged_rule = module.section_defaults.copy()
                        # Update the merged rule with the actual rule, preserving the rule's original keys
                        merged_rule.update(rule)
                        # Now the merged_rule is a dictionary that describes the rule that is going to be created
                        # here you can add some code
                        # that validates the complaince of the rule with your requirements
                        # such as a naming convention or a presence of a non-default description

                        # ------ validation code starts -----
                        if settings.PERFORM_VALIDATION_CHECKS and settings.VALIDATE_RULE_NAMES:
                            if not validate_string_for_compliance(merged_rule['name'],
                                                                  settings.VALIDATION_PATTERN_FOR_RULE_NAMES,
                                                                  "rule name",
                                                                  "is not compliant with the naming convention"):
                                list_of_invalid_rules.append(merged_rule['name'])

                        if settings.PERFORM_VALIDATION_CHECKS and settings.VALIDATE_RULE_DESCRIPTIONS:
                            if not validate_string_for_compliance(merged_rule['description'],
                                                           settings.VALIDATION_PATTERN_FOR_RULE_DESCRIPTIONS,
                                                           "rule description",
                                                           "is not compliant with the naming convention (must be from 12 to 1024 characters long)"):
                                list_of_invalid_rules.append(merged_rule['name'])
                        # ------ validation code ends -------

                        # append the rule to the list of rules
                        updated_rules.append(merged_rule)
                        all_subfolder_names.append(folder_name)  # Append folder name for each rule
                    all_rules.extend(updated_rules)

    # validation action (after we parsed all rules in all folders)
    if settings.PERFORM_VALIDATION_CHECKS and list_of_invalid_rules:
        console.print(f"Here is the list of all policy rules with invalid name and/or description: {list(set(list_of_invalid_rules))}")
        console.print(f"You can make the script terminate on validation errors by setting the [bold]SOFT_VALIDATION_ONLY[/bold] flag to [bold]False[/bold].")
        if not settings.SOFT_VALIDATION_ONLY:
            console.print(f"The validation errors are causing the program to exit now (you can change "
                          f"this behavior by setting the [bold]SOFT_VALIDATION_ONLY[/bold] setting to [bold]True[/bold]).")
            console.print(f"It's recommended you roll back all changes made by the script, fix "
                          f"the issue in the code and restart the script.")
            console.print(f"All changes made can be rolled back by issuing the command '[bold italic]load config "
                          f"from running-config.xml[/bold italic]' in the CLI '[bold italic]configure[/bold italic]' mode.")
            sys.exit(1)

    return all_rules, all_subfolder_names


def validate_string_for_compliance(string_to_validate, regex_pattern, validated_entity_name, message_to_display_if_no_match):
    """
    Validates a string against a given regex pattern and displays a message if the validation fails.

    This function checks whether the provided string matches a specified regular expression pattern.
    If the string does not match, a validation error message is displayed using formatted console output.
    The function then returns `False` to indicate non-compliance. Otherwise, it returns `True` when the
    string is fully compliant.

    Args:
        string_to_validate: The string to be validated against the provided regex pattern.
        regex_pattern: A regular expression pattern that the string should match.
        validated_entity_name: The name of the entity being validated, used for generating meaningful
            error messages.
        message_to_display_if_no_match: A message that will be appended in the console output when
            validation fails.
    """
    # Compile the passed regex pattern
    pattern = re.compile(regex_pattern)
    # Check if there is a match
    if not pattern.fullmatch(string_to_validate):
        console.print(f"[bold red]Validation Error:[/bold red] "
                      f"The {validated_entity_name} "
                      f"[bold]'{string_to_validate}'[/bold] "
                      f"{message_to_display_if_no_match}.")
        return False # Return False to take action in the main code
    else:
        return True # Return if the string is compliant with the pattern


def pluralize(word):
    """
    Converts a singular word to its plural form.

    This function handles the pluralization of singular words based on specific
    conditions. If the word ends with a 'y' and is preceded by a consonant, it changes
    'y' to 'ies'. Otherwise, it simply adds 's' for pluralization.

    Args:
        word (str): A singular English word that needs to be converted to its
            plural form.

    Returns:
        str: The pluralized form of the input word.
    """
    if re.search(r'y$', word) and not re.search(r'[aeiou]y$', word):
        return re.sub(r'y$', 'ies', word)
    return word + 's'


def version_tuple(version_str):
    """
    Convert a version string to a tuple of integers for comparison.

    Args:
        version_str (str): Version string in format "x.y.z"

    Returns:
        tuple: Tuple of integers representing the version
    """
    return tuple(map(int, version_str.split('.')))


def load_menu_options() -> dict | None:
    """
    Loads menu options (policy targets) from a JSON file defined by the global
    constant `POLICY_TARGETS_FILENAME`.

    Returns:
        dict or None: The loaded menu options or None if loading failed.
    """
    global menu_options

    # Check if installed module versions meet minimum requirements
    pan_os_python_version = metadata.version("pan-os-python")
    pan_python_version    = metadata.version("pan-python")

    # Display version information if verbose output is enabled
    if settings.VERBOSE_OUTPUT:
        version_info = (f'pan-os-python: v{pan_os_python_version}'
                        f'\npan-python:    v{pan_python_version}')
        version_panel = Panel.fit(version_info, style="dim", title=f"Project v{settings.POLICY_VERSION}", border_style="dim")
        console.print(version_panel)

    # Check if versions meet minimum requirements
    if version_tuple(pan_os_python_version) < version_tuple(settings.MIN_PAN_OS_PYTHON_VERSION):
        console.print(f"[bold red]ERROR:[/bold red] pan-os-python version {pan_os_python_version} is lower than the required minimum version {settings.MIN_PAN_OS_PYTHON_VERSION}")
        return None

    if version_tuple(pan_python_version) < version_tuple(settings.MIN_PAN_PYTHON_VERSION):
        console.print(f"[bold red]ERROR:[/bold red] pan-python version {pan_python_version} is lower than the required minimum version {settings.MIN_PAN_PYTHON_VERSION}")
        return None

    # Load menu options from JSON file
    menu_options = parse_metadata_from_json("Menu Options", settings.POLICY_TARGETS_FILENAME)
    if menu_options is None:
        print(f"Failed to load menu options from {settings.POLICY_TARGETS_FILENAME}. Aborting script execution...")
        return None
    return menu_options


def display_menu() -> None:
    """
    Displays a menu of options for the user to select from.

    Prints each option with a numbered list. The default choice, if specified,
    is indicated with an asterisk. Prompts the user to select an option,
    notifying about the default option when pressing Enter.
    """
    # Check if default_choice is a valid key in menu_options
    valid_default = default_choice in menu_options if menu_options and default_choice else False
    
    # Determine which option should be marked as default
    effective_default = default_choice if valid_default else list(menu_options.keys())[0] if menu_options else None

    menu_content = "Please select an option (press Enter for default *):\n\n"
    for i, option in enumerate(menu_options, 1):
        default_indicator = " * " if option == effective_default else "   "
        menu_content += f"{default_indicator} {i}. {option}\n"
    
    # Add exit option
    menu_content += f"\n    0. Exit\n"
    
    # Add note about where to update menu options
    menu_content += f"\n[dim]Note: Menu options are defined in {settings.POLICY_TARGETS_FILENAME}[/dim]"

    panel = Panel.fit(menu_content, title="Select the policy deployment target", border_style="blue")
    console.print(panel)


def get_user_choice() -> int:
    """
    Prompts the user to select an option from a list of choices.

    The options are indexed starting from 1 up to the number of available options. The user is prompted to enter
    their choice as a number within this range. If the user simply presses Enter without entering a number,
    the function returns the index of the default option. If the user enters 0, the function returns 0 to indicate
    the exit option was selected.

    Returns:
        int: The index of the user's selected choice, the index of the default choice if no input is provided,
             or 0 if the exit option was selected.
    """
    num_options = len(menu_options)
    # Check if default_choice is a valid key in menu_options
    valid_default = default_choice in menu_options if menu_options and default_choice else False
    # Determine which option should be used as default
    effective_default = default_choice if valid_default else list(menu_options.keys())[0] if menu_options else None
    
    while True:
        try:
            choice = input(f"\nEnter your choice (0-{num_options}, Enter for default *): ").strip()
            if choice == "":
                if effective_default:
                    return list(menu_options.keys()).index(effective_default) + 1  # Return the index of the effective default choice
                else:
                    # This should not happen if menu_options is properly loaded
                    print("\nNo default option available. Please make a selection.")
                    continue
            choice = int(choice)
            if choice == 0:  # Exit option
                return 0
            elif 1 <= choice <= num_options:
                return choice
            else:
                print(f"\nPlease enter a number between 0 and {num_options}, or press Enter for default.")
        except ValueError:
            print("Invalid input, please enter a number or press Enter for the default option.")
