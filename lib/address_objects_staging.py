"""
Functions for managing address objects and groups in PAN-OS.

This module provides functionality to:

- Stage address objects and groups from various sources (CSV files, GitHub API, DNS)
- Compare current and desired address objects/groups configurations
- Calculate deltas (redundant, modified, and new objects)
- Delete redundant objects and update modified ones
- Create static and dynamic address groups
- Handle address objects for Active Directory Domain Controllers
"""

import settings
import requests
import dns.resolver
import urllib3

from rich import print
from ngfw.objects.tags.tags import tags
from panos.panorama         import DeviceGroup
from lib.auxiliary_functions import find_address_groups_delta, find_address_objects_delta
from lib.auxiliary_functions import parse_metadata_from_csv, execute_multi_config_api_call
from panos.objects          import AddressObject, AddressGroup, DynamicUserGroup


def handle_address_objects_and_groups(object_container, panos_device):
    """
    Handles address objects and groups synchronization between a firewall's current
    configuration and a desired staging configuration.

    This function performs the following operations:

    - Retrieves and displays current address objects and groups from the firewall.
    - Stages new address objects and groups from the provided staging data group.
    - Identifies redundant, modified, and new address objects and groups.
    - Deletes redundant and updated objects/groups from the current configuration.
    - Recreates the delta (new/modified) address objects and groups.

    Args:
        panos_device:
        object_container (vsys or device group):
        staging_dg (DeviceGroup): The staging device group containing desired address objects
                                  and groups to synchronize with the firewall.
    """
    panos_device.add(object_container)

    # =====================================================================================================
    # Get current address objects
    print('Looking for existing address objects...', end='')
    current_address_objects = AddressObject.refreshall(object_container)
    print(f"found {len(current_address_objects)} address objects", end="")
    if settings.VERBOSE_OUTPUT and len(current_address_objects) != 0:
        print(':')
        for address_object in current_address_objects: print(f'\t - {address_object.name}')

    # =====================================================================================================
    # Get current address object groups
    print('Looking for existing address groups...', end='')
    current_address_groups = AddressGroup.refreshall(object_container)
    print(f'found {len(current_address_groups)} address groups', end='')
    if settings.VERBOSE_OUTPUT and len(current_address_groups) != 0:
        print(':')
        for address_object_group in current_address_groups: print(f'\t - {address_object_group.name}')

    # Create a temporary virtual device group to stage address object creation
    # we're not going to attach it to anything as its only purpose
    # is to help calculate delta of address objects that need to be deleted/added/updated
    staging_dg = DeviceGroup("staging")

    # =====================================================================================================
    # Take the staging device group and create all necessary address objects and groups in this group
    # (all objects that need to exist according to the CSV file(s) on disk, and from all other sources)
    stage_address_objects(staging_dg)

    # Now we take objects of different type in this DG and separate them into groups
    staged_address_objects          = []
    staged_address_groups           = []
    staged_dynamic_user_groups      = []
    for child in staging_dg.children:
         if type(child) is AddressObject:
             staged_address_objects.append(child)
         if type(child) is AddressGroup:
             staged_address_groups.append(child)
         if type(child) is DynamicUserGroup:
             staged_dynamic_user_groups.append(child)

    # =====================================================================================================
    # Cross-reference current address objects with desired objects to establish the delta
    # (redundant, changed and new objects)
    print('Calculating redundant, modified and new address objects...', end='')
    delta_current_addresses, delta_staged_addresses = find_address_objects_delta(current_address_objects, staged_address_objects)
    print("done")

    print(f'\tFound: {len(delta_current_addresses)} redundant addresses')
    print(f'\tFound: {len(delta_staged_addresses)} modified or new addresses')

    # Output the redundant addresses
    if settings.VERBOSE_OUTPUT and len(delta_current_addresses) != 0:
        for address_object in delta_current_addresses:
            print(f'\t - Redundant address:       {address_object.name}')

    # Output the updated/new addresses
    if settings.VERBOSE_OUTPUT and len(delta_staged_addresses) != 0:
        for address_object in delta_staged_addresses:
            print(f'\t - Modified or new address: {address_object.name}')

    # =====================================================================================================
    # Cross-reference current address groups with desired objects to establish the delta
    print('Calculating redundant, modified or new address groups...', end='')
    delta_current_groups, delta_staged_groups = find_address_groups_delta(current_address_groups, staged_address_groups)
    print("done")

    print(f'\tFound: {len(delta_current_groups)} redundant groups')
    print(f'\tFound: {len(delta_staged_groups)} modified or new groups')

    if settings.VERBOSE_OUTPUT and len(delta_current_groups) != 0:
        for address_group in delta_current_groups:
            print(f'\t - Redundant group:       {address_group.name}')

    delta_staged_group_names = []
    if settings.VERBOSE_OUTPUT and len(delta_staged_groups) != 0:
        for address_group in delta_staged_groups:
            delta_staged_group_names.append(address_group.name)
            print(f'\t - Modified or new group: {address_group.name}')

    # =====================================================================================================
    # Empty the current address object groups that match names of the delta groups (they somehow changed and
    # need to be recreated)
    # if len(current_address_groups) != 0 and len(delta_staged_group_names) != 0:
    #     print("Emptying the content of redundant, new or updated groups (so that they can be deleted)...")
    #     for group in current_address_groups:
    #         if group.name in delta_staged_group_names:
    #             print(f"\t - new/updated: {group.name:<64}")
    #             group.static_value = []
    #             group.update(variable='static_value')
    #     for group in delta_current_groups:
    #         print(f"\t - redundant: {group.name:<64}")
    #         group.static_value = []
    #         group.update(variable='static_value')


    # =====================================================================================================
    # Delete empty delta and redundant address groups
    if len(current_address_groups) != 0 and len(delta_staged_groups) != 0:
        print("Staging updated and redundant groups for deletion:")
        action_id = 1
        multi_config_xml = '<multi-config>'
        # Here we stage deletion of current groups that were updated
        for group in set(delta_current_groups + delta_staged_groups):
            if object_container.find(group.name, AddressGroup):
                multi_config_xml += f'<delete id="{action_id}" xpath="{object_container.find(group.name, AddressGroup).xpath()}"></delete>'
                if settings.VERBOSE_OUTPUT: print(f"\tStaged for deletion: {action_id:>6} {group.name:<64}")
                object_container.remove(object_container.find(group.name, AddressGroup))
            action_id += 1
        multi_config_xml += '</multi-config>'
        # Now we delete all groups staged for deletion
        execute_multi_config_api_call(panos_device, multi_config_xml, "Performing the staged operation(s)...", 0)


    # =====================================================================================================
    # Delete delta and redundant addresses from the current config:
    if len(current_address_objects) != 0:
        print("Staging the updated and redundant addresses for deletion:")
        action_id = 1
        multi_config_xml = '<multi-config>'
        for address in delta_current_addresses:
            multi_config_xml += f'<delete id="{action_id}" xpath="{address.xpath()}"></delete>'
            if settings.VERBOSE_OUTPUT: print(f"\tStaged for deletion: {action_id:>6} - {address.name:<64}")
            object_container.remove(address)
            action_id += 1
        for address in delta_staged_addresses:
            object_container.add(address) # we temporarily add the staged address to the config tree so that
                            # calculation of the XPath worked at the next step
            multi_config_xml += f'<delete id="{action_id}" xpath="{address.xpath()}"></delete>'
            if settings.VERBOSE_OUTPUT: print(f"\tStaged for deletion: {action_id:>6} - {address.name:<64}")
            object_container.remove(address)
            action_id += 1
        multi_config_xml += '</multi-config>'
        # Now we delete all address objects staged for deletion
        execute_multi_config_api_call(panos_device, multi_config_xml, "Performing the staged operation(s)...", 0)

    # =====================================================================================================
    # (Re)create the delta address objects
    if len(delta_staged_addresses) != 0:
        print("Staging the updated address objects for creation:")
        action_id = 1
        multi_config_xml = '<multi-config>'
        for address in delta_staged_addresses:
            object_container.add(address)
            if settings.VERBOSE_OUTPUT: print(f"\tStaged for creation: {action_id:>6} - {address.name:<64}")
            multi_config_xml += f'<edit id="{action_id}" xpath="{address.xpath()}">{address.element_str().decode()}</edit>'
            action_id += 1
        multi_config_xml += '</multi-config>'
        execute_multi_config_api_call(panos_device, multi_config_xml, "Performing the staged operation(s)...", 0)

    # =====================================================================================================
    # (Re)create the delta address groups
    if len(delta_staged_groups) != 0:
        print("Staging the updated/new address groups for creation:")
        action_id = 1
        multi_config_xml = '<multi-config>'
        for group in delta_staged_groups:
            object_container.add(group)
            if settings.VERBOSE_OUTPUT: print(f"\tStaged for creation: {action_id:>6} - {group.name:<64}")
            multi_config_xml += f'<edit id="{action_id}" xpath="{group.xpath()}">{group.element_str().decode()}</edit>'
            action_id += 1
        multi_config_xml += '</multi-config>'
        execute_multi_config_api_call(panos_device, multi_config_xml, "Performing the staged operation(s)...", 0)


def stage_address_objects(staging_dg):
    """
    Staging of address objects involves the retrieval and parsing of address data from various sources
    including GitHub API, CSV files, DNS for Active Directory Domain Controllers, and creation of both
    static and dynamic address groups. This function organizes and adds these address objects and
    groups to the provided device group.

    Args:
        staging_dg (DeviceGroup): Device Group instance where address objects and groups will be staged.
    """
    print("Pre-staging all address objects and groups...")

    # ########################################################################################################
    # Address objects for Git over SSH to GitHub (we are retrieving up-to-date addresses from GitHub)
    # ########################################################################################################
    print(f'\tRetrieving current GitHub Git-over-SSH addresses...', end='')
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get('https://api.github.com/meta', verify=settings.CERTIFICATE_BUNDLE_FILENAME)
    data = response.json()
    git_section = data['git']
    ipv4_ips = [ip for ip in git_section if ':' not in ip]
    ip_names_github = list()
    for ip in ipv4_ips:
        ip_name = 'H-github-' + ip.replace('/', '_')
        ip_names_github.append(ip_name)
        staging_dg.add(AddressObject(name=ip_name, type='ip-netmask', value=ip,
                                     description='GitHub Address/Subnet used for Git'))
    print(f'{len(ip_names_github)} address(es) found.')

    ###########################################################################################################
    # Creating all address objects from CSV
    # Import static objects from a spreadsheet
    address_objects = parse_metadata_from_csv("Address Objects", settings.ADDRESS_OBJECTS_FILENAME)

    # Now we parse all address objects from the CSV looking for ones with empty Tags field
    # Tagged and non-tagged objects cannot be mixed up in one bulk object creation operation
    count = 0
    for address in address_objects:
        if address['Type'] != 'Static group':
            # Convert human-readable types from the CSV file to exact API keywords
            if address['Type'] == 'IP Wildcard':
                address_type = 'ip-wildcard'
            elif address['Type'] == 'IP Range':
                address_type = 'ip-range'
            elif address['Type'] == 'FQDN':
                address_type = 'fqdn'
            else:
                address_type = 'ip-netmask' # default value

            # convert the Tags field to a list or set to None if it's an empty string
            normalized_tags = address['Tags']
            if normalized_tags == '': normalized_tags = None
            else:
                # Tags are converted into a list
                normalized_tags = normalized_tags.split(';')
                # We also strip leading and trailing spaces from each of them
                normalized_tags = [x.strip(' ') for x in normalized_tags]

            # set the Description to None if it's an empty string
            normalized_description = address['Description'].strip()
            if normalized_description == '': normalized_description = None

            # We add each found object to the target device group/firewall
            staging_dg.add(AddressObject(name=address['Name'].strip(),
                                         type=address_type,
                                         value=address['Address'].strip(),
                                         description=normalized_description,
                                         tag=normalized_tags))
            count += 1


    staging_dg.add(AddressGroup(name='AG-github_git', static_value=ip_names_github, description='This group contains all addresses declared by GitHub as the '
                                                         'ones used for GIT (as per https://api.github.com/meta)'))

    # Updating the list of DCs if required
    if settings.UPDATE_AD_DC_LIST:
        print(f'\tRetrieving the current list of AD Domain Controllers and creating address objects accordingly...', end='')
        dc_dict   = {}
        answers   = dns.resolver.resolve('_ldap._tcp.dc._msdcs.' + settings.AD_DOMAIN_NAME_DNS, 'SRV')
        for rdata in answers:
            # Split the FQDN to extract the hostname (remove the domain name)
            dc_name = rdata.target.to_text(omit_final_dot=True).split('.')[0]
            # Query DNS for the A record of the domain controller
            ip_answers = dns.resolver.resolve(dc_name + '.' + settings.AD_DOMAIN_NAME_DNS, 'A')
            for ip_rdata in ip_answers:
                dc_ip = ip_rdata.to_text()
                key = 'H-' + dc_name + '-' + dc_ip + '_32'
                value = dc_ip + '/32'
                dc_dict[key] = value
        print(f'{len(dc_dict)} DCs found; creating address objects...', end='')
        for key, value in dc_dict.items():
            staging_dg.add(AddressObject(tag=[settings.tag_ad_dc], name=key, type='ip-netmask',
                                         value=value, description=f"Domain Controller for '{settings.AD_DOMAIN_NAME}'"))
        print('done')

    # Creating Dynamic Address groups:
    print(f'\tDynamic Address Groups...', end='')
    staging_dg.add(AddressGroup(name='DAG-domain-controllers',
                                description='This dynamic group contains all AD Domain Controllers',
                                dynamic_value=f"'{tags["ad-dc"]["name"]}'"))

    staging_dg.add(AddressGroup(name='DAG-compromised_hosts',
                                description='This dynamic address group contains allegedly compromised hosts '
                                                         '- the ones that attempted to reach a C&C destination.',
                                dynamic_value=f"'{tags["compromised-host"]["name"]}'"))

    staging_dg.add(AddressGroup(name='DAG-tls_d_auto_exceptions',
                                description='TLS-connections to these IP-addresses had been attempted to be decrypted but failed',
                                dynamic_value=f"'{tags["tls-d-exceptions-auto"]["name"]}'"))
    print('done')

    # Creating Dynamic User groups:
    print(f'\tDynamic User Groups...', end='')
    staging_dg.add(DynamicUserGroup(name='DUG-compromised_users',
                                    description='This dynamic user group contains allegedly compromised users '
                                                             '- the ones that attempted to reach a C&C destination.',
                                    filter=f"'{tags["compromised-user"]["name"]}'",
                                    tag=[tags["compromised-user"]["name"]]))
    print('done')

    # =================================================================================
    # Creating static groups:
    print(f'\tStatic address object groups...', end='')
    # First of all we begin with building a list of all address object groups
    all_referenced_groups = []
    for entry in address_objects:
        if entry['Group Name'] is not None and entry['Group Name'] != '' and entry['Type'] != 'Static Group':
            if entry['Group Name'].startswith('AG-'):
                all_referenced_groups.append(entry['Group Name'])
            else:
                print(f'Found a group with incorrect group name: {entry["Group Name"]}. This group will not be created.')

    # Dedupe the list of address object groups
    all_referenced_groups = list(dict.fromkeys(all_referenced_groups))
    print(f'{len(all_referenced_groups)} groups found...', end='')

    # Now we create each of the address object groups
    for group in all_referenced_groups:
        group_members     = []
        group_description = ''
        for entry in address_objects:
            if entry['Type'] != 'Static Group' and entry['Group Name'] == group:
                group_members.append(entry['Name'].strip())
                if entry['Group Description'] != '':
                    group_description = entry['Group Description'].strip()
        # Now we add the group object to the device group
        normalized_description = group_description if group_description != '' else None
        staging_dg.add(AddressGroup(name=group.strip(), static_value=group_members, description=normalized_description))

    # ==============================================================================
    # Now we look for groups that are members of other groups
    all_referenced_groups = []
    for entry in address_objects:
        if entry['Group Name'] != '' and entry['Type'] == 'Static Group':
            if entry['Group Name'].startswith('AG-'):
                all_referenced_groups.append(entry['Group Name'])
            else:
                print(f'\tFound a group with incorrect group name: {entry["Group Name"]}. This group will not be created.')
    # Dedupe the list of address object groups
    all_referenced_groups = list(dict.fromkeys(all_referenced_groups))

    # Now we create each of the address object groups
    for group in all_referenced_groups:
        group_members     = []
        group_description = ''
        for entry in address_objects:
            if entry['Type'] == 'Static Group' and entry['Group Name'] == group:
                group_members.append(entry['Name'])
                if entry['Group Description'] != '':
                    group_description = entry['Group Description']
        # Now we add the group object to the device group
        normalized_description = group_description if group_description != '' else None
        staging_dg.add(AddressGroup(name=group, static_value=group_members, description=normalized_description))
    print("")
