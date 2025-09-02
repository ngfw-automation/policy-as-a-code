"""
Functions for creating and managing NAT policies in PAN-OS.

This module provides functionality to:

- Import NAT rules from configuration files
- Handle domain prefixes for user identities based on device type
- Create NAT rules with appropriate parameters for both standalone firewalls and Panorama
- Support group tagging for policy organization
- Process rule attributes like zones, addresses, users, services, and actions
"""

import  settings
from    panos.firewall          import Firewall
from    panos.panorama          import Panorama
from    panos.policies          import NatRule
from    lib.auxiliary_functions  import find_and_import_rules
from rich import print
from rich.console import Console
from rich.table import Table


def nat_policy(panos_device, root_policy_folder, target_environment):
    """
    Create a list of NAT rules by parsing and processing rule definitions from the specified folder.

    Args:
        panos_device: The PAN-OS device object (Firewall or Panorama).
        root_policy_folder: The folder containing the NAT rule definitions.
        target_environment: The target environment for the policy (e.g., "lab" or "prod").

    Returns:
        tuple: A tuple containing two elements:
            - A list of NAT rule objects.
            - A set of deduplicated group tags used in the NAT policy.
    """

    # Determine domain prefix based on target environment
    if target_environment.lower() == "lab" and settings.ADD_DOMAIN_PREFIX_FOR_LAB:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    elif target_environment.lower() == "prod" and settings.ADD_DOMAIN_PREFIX_FOR_PROD:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    else:
        domain_prefix = ''

    rules = []

    # Import rules from the given folder
    complete_list_of_rules, all_group_tags = find_and_import_rules(root_policy_folder)

    # Create a table for displaying rules
    console = Console()
    if settings.VERBOSE_OUTPUT:
        # Set the table title based on the folder parameter
        if "PRE" in root_policy_folder:
            table_title = "NAT Policy Pre-Rules"
        elif "POST" in root_policy_folder:
            table_title = "NAT Policy Post-Rules"
        else:
            table_title = "NAT Policy Rules"

        table = Table(title=table_title)
        table.add_column("Group Tag", style="cyan")
        table.add_column("Rule Name", style="green")

    for rule, group_tag in zip(complete_list_of_rules, all_group_tags):
        # go through all imported rules and add domain prefix to the username if required
        # (unless it's one of the predefined PAN-OS values)
        if rule['source_users'] not in ['any', 'known-user', 'unknown', 'pre-logon', None] and domain_prefix:
            source_user = domain_prefix + rule['source_users']
        else:
            source_user = rule['source_users']

        # Add the rule to the table if verbose output is enabled
        if settings.VERBOSE_OUTPUT:
            table.add_row(
                rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,
                rule['name']
            )

        # 1st step: construct the rule object based on the data
        #
        # for standalone firewalls we exclude Target-related attributes
        if isinstance(panos_device, Firewall):
            rules.append(NatRule(
                name                            =rule['name'],
                description                     =rule['description'],
                tags                            =rule['tags'],
                group_tag                       =rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,  # Group Tag

                source_zones                    =rule['source_zones'],
                source_addresses                =rule['source_addresses'],
                negate_source                   =rule['negate_source'],
                source_users                    =source_user,
                source_hip                      =rule['source_hip'],

                destination_zones               =rule['destination_zones'],
                destination_addresses           =rule['destination_addresses'],
                negate_destination              =rule['negate_destination'],
                destination_hip                 =rule['destination_hip'],

                services                        =rule['services'],
                url_categories                  =rule['url_categories'],

                action                          =rule['action'],
                decryption_type                 =rule['decryption_type'],
                decryption_profile              =rule['decryption_profile'],

                log_setting                     =rule['log_setting'],
                log_successful_tls_handshakes   =rule['log_successful_tls_handshakes'],
                log_failed_tls_handshakes       =rule['log_failed_tls_handshakes'],

                disabled                        =rule['disabled']                  # Rule is disabled
            ))
        # for Panorama, we keep Target-related attributes found in the source 'rules.py' files
        else:
            rules.append(NatRule(
                name                            =rule['name'],
                description                     =rule['description'],
                tags                            =rule['tags'],
                group_tag                       =rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,  # Group Tag

                source_zones                    =rule['source_zones'],
                source_addresses                =rule['source_addresses'],
                negate_source                   =rule['negate_source'],
                source_users                    =source_user,
                source_hip                      =rule['source_hip'],

                destination_zones               =rule['destination_zones'],
                destination_addresses           =rule['destination_addresses'],
                negate_destination              =rule['negate_destination'],
                destination_hip                 =rule['destination_hip'],

                services                        =rule['services'],
                url_categories                  =rule['url_categories'],

                action                          =rule['action'],
                decryption_type                 =rule['decryption_type'],
                decryption_profile              =rule['decryption_profile'],

                log_setting                     =rule['log_setting'],
                log_successful_tls_handshakes   =rule['log_successful_tls_handshakes'],
                log_failed_tls_handshakes       =rule['log_failed_tls_handshakes'],

                target                          =rule['target'],                   # Target devices
                negate_target                   =rule['negate_target'],            # Target is negated
                disabled                        =rule['disabled']                  # Rule is disabled
            ))

    # Now we create a deduplicated set of group tags used in the current section of the policy
    all_group_tags = []
    if settings.USE_FOLDER_NAMES_AS_GROUP_TAGS:
        all_group_tags = all_group_tags
    else:
        for t in complete_list_of_rules:
            if 'group_tag' in t:
                if t['group_tag'] not in all_group_tags:
                    all_group_tags.append(t['group_tag'])

    all_group_tags_deduped = set(all_group_tags)

    # Display the table if the verbose output is enabled
    if settings.VERBOSE_OUTPUT:
        console.print(table)

    # This is the end of the NAT rule base
    # Now we return the list of created rules to the caller of this function
    return rules, all_group_tags_deduped
