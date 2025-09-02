"""
Functions for creating and managing pre-rulebase security policies in PAN-OS.

This module provides functionality to:

- Create security rules for the pre-rulebase section of the policy
- Import rule definitions from external files
- Process and apply security profiles to rules
- Support domain prefixing for user identities
- Preserve rule UUIDs for consistent policy management
- Create custom application-specific rules (e.g., GitHub Git access)
- Handle different rule attributes for standalone firewalls vs. Panorama
"""

from ngfw.objects.tags.group_tags import group_tags

from panos.policies import SecurityRule as R
import settings
from panos.firewall import Firewall
from lib.auxiliary_functions import find_and_import_rules
from rich.console import Console
from rich.table import Table

def security_policy_pre(app_categories, security_rules_uuids, panos_device, target_environment):
    """
    Create a list of rules for the PRE section of the policy by parsing and processing rule definitions from 'rules.py' files.
    The parsing is done by the external function find_and_import_rules().

    Args:
        app_categories: A list of application categories, each represented as a dictionary containing details like "Category" and "UserID".
        security_rules_uuids: A dictionary mapping rule names to their UUIDs.
        panos_device: The PAN-OS device object (Firewall or Panorama).
        target_environment: The target environment for the policy (e.g., "lab" or "prod").

    Returns:
        tuple: A tuple containing two elements:
            - A list of security rule objects constructed based on the provided policy rules.
            - A set of deduplicated group tags used in the PRE section of the policy.
    """

    # Determine domain prefix based on target environment
    if target_environment.lower() == "lab" and settings.ADD_DOMAIN_PREFIX_FOR_LAB:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    elif target_environment.lower() == "prod" and settings.ADD_DOMAIN_PREFIX_FOR_PROD:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    else:
        domain_prefix = ''

    rules = []

    # Import security rules from [ngfw/policies/security/PRE]
    complete_list_of_pre_rules, all_group_tags = find_and_import_rules(settings.SECURITY_RULES_PRE_FOLDER)

    # Create a table for displaying rules
    console = Console()
    if settings.VERBOSE_OUTPUT:
        table = Table(title="Security Policy Pre-Rules")
        table.add_column("Group Tag", style="cyan")
        table.add_column("Rule Name", style="green")

    for rule, group_tag in zip(complete_list_of_pre_rules, all_group_tags):
        # go through all imported rules and add domain prefix to the username if required
        # (unless it's one of the predefined PAN-OS values)
        if rule['source_user'] not in ['any', 'known-user', 'unknown', 'pre-logon', None] and domain_prefix:
            source_user = domain_prefix + rule['source_user']
        else:
            source_user = rule['source_user']

        # set UUID to what it was set in the policy that existed prior to the script
        # (thus UUID will be preserved provided the old policy had a rule with identical name)
        uuid = security_rules_uuids.get(rule['name'], None)

        # Add rule to the table if verbose output is enabled
        if settings.VERBOSE_OUTPUT:
            table.add_row(
                rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,
                rule['name']
            )

        # 1st step: construct the rule object based on the data
        #
        # for standalone firewalls we exclude Target-related attributes
        if isinstance(panos_device, Firewall):
            rules.append(R(
                name                =rule['name'],                     # Name of the rule
                uuid                =uuid,                             # rule UUID
                type                =rule['type'],                     # Rule type (universal|interzone|intrazone)
                description         =rule['description'],              # Description
                tag                 =rule['tag'],                      # Tag(s)
                group_tag           =rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,  # Group Tag

                fromzone            =rule['fromzone'],                 # Source Zone(s)
                source              =rule['source'],                   # Source Address(es)
                negate_source       =rule['negate_source'],            # Negate Source
                source_user         =source_user,                       # Source User (with optional prefix)

                tozone              =rule['tozone'],                   # Destination Zone(s)
                destination         =rule['destination'],              # Destination Address(es)
                negate_destination  =rule['negate_destination'],       # Negate destination
                application         =rule['application'],              # Application(s)
                service             =rule['service'],                  # Service(s)
                category            =rule['category'],                 # URL categories

                action              =rule['action'],                   # Action

                group               =rule['group'],                    # Profile Group
                virus               =rule['virus'],                    # Antivirus Security Profile
                spyware             =rule['spyware'],                  # Anti-Spyware Security Profile
                vulnerability       =rule['vulnerability'],            # Vulnerability Protection Security Profile
                url_filtering       =rule['url_filtering'],            # URL Filtering Security Profile
                file_blocking       =rule['file_blocking'],            # File Blocking Security Profile
                wildfire_analysis   =rule['wildfire_analysis'],        # Wildfire Analysis Security Profile
                data_filtering      =rule['data_filtering'],           # Data Filtering Security Profile

                log_setting         =rule['log_setting'],              # Log Forwarding Profile
                log_start           =rule['log_start'],                # Log session start
                log_end             =rule['log_end'],                  # Log session end

                disabled            =rule['disabled']                  # Rule is disabled
            ))
        # for Panorama, we keep Target-related attributes found in the source 'rules.py' files
        else:
            rules.append(R(
                name                =rule['name'],                     # Name of the rule
                uuid                =uuid,                             # rule UUID
                type                =rule['type'],                     # Rule type (universal|interzone|intrazone)
                description         =rule['description'],              # Description
                tag                 =rule['tag'],                      # Tag(s)
                group_tag           =rule['group_tag'] if not settings.USE_FOLDER_NAMES_AS_GROUP_TAGS else group_tag,  # Group Tag

                fromzone            =rule['fromzone'],                 # Source Zone(s)
                source              =rule['source'],                   # Source Address(es)
                negate_source       =rule['negate_source'],            # Negate Source
                source_user         =source_user,                       # Source User (with optional prefix)

                tozone              =rule['tozone'],                   # Destination Zone(s)
                destination         =rule['destination'],              # Destination Address(es)
                negate_destination  =rule['negate_destination'],       # Negate destination
                application         =rule['application'],              # Application(s)
                service             =rule['service'],                  # Service(s)
                category            =rule['category'],                 # URL categories

                action              =rule['action'],                   # Action

                group               =rule['group'],                    # Profile Group
                virus               =rule['virus'],                    # Antivirus Security Profile
                spyware             =rule['spyware'],                  # Anti-Spyware Security Profile
                vulnerability       =rule['vulnerability'],            # Vulnerability Protection Security Profile
                url_filtering       =rule['url_filtering'],            # URL Filtering Security Profile
                file_blocking       =rule['file_blocking'],            # File Blocking Security Profile
                wildfire_analysis   =rule['wildfire_analysis'],        # Wildfire Analysis Security Profile
                data_filtering      =rule['data_filtering'],           # Data Filtering Security Profile

                log_setting         =rule['log_setting'],              # Log Forwarding Profile
                log_start           =rule['log_start'],                # Log session start
                log_end             =rule['log_end'],                  # Log session end

                target              =rule['target'],                   # Target devices
                negate_target       =rule['negate_target'],            # Target is negated
                disabled            =rule['disabled']                  # Rule is disabled
            ))
        # No need for "done" print statement as we're using a table

    # In this section you can create some custom logic to meet requirements of specific applications
    #
    # The example rule below shows how we could create a rule allowing Git communication with GitHub
    # provided that the Management category is a managed one as per the business requirements.
    #
    # The rule accounts both for Git-over-HTTPS (App-ID signatures ssl, git and github-base)
    # and Git-over-SSH (App-ID signatures ssh and github-base). Obviously, we do not want to allow
    # SSH to any public external IP-address therefore we limit the destinations to an address group AG-github_git
    # that in turn is dynamically built based on the information published by GitHub at the time of the policy
    # creation along with all other address objects
    #
    uuid = security_rules_uuids.get('github-git', None)

    # 1st step: we retrieve the UserID information for the Management category that GitHub belongs to
    for category in app_categories:
        if category["Category"].lower() == 'management' and category["Action"].lower() == settings.APP_ACTION_MANAGE:
            category_management_group = domain_prefix + category["UserID"].lower()

            # Add GitHub Git rule to the table if verbose output is enabled
            if settings.VERBOSE_OUTPUT:
                table.add_row(
                    group_tags["business-apps"]["name"],
                    'github-git'
                )
            # 2nd step: we create the rule
            rules.append(R(name='github-git',
                           uuid=uuid,
                           source_user=category_management_group,
                           group='PG-apps-regular', fromzone=settings.ZONE_INSIDE,
                           tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS,
                           destination=['AG-github_git'],
                           application=['ssh', 'github-base', 'git', 'ssl'], service=['application-default'],
                           action='allow',
                           tag=group_tags["business-apps"]["name"],
                           group_tag=group_tags["business-apps"]["name"],
                           log_setting=settings.LFP_DEFAULT, log_start=False,
                           log_end=True,
                           description=f'This rule allows to use Git over SSH and HTTPS with GitHub'))

    # Now we create a deduplicated set of tags used in the PRE section of the policy
    all_pre_group_tags = []
    if settings.USE_FOLDER_NAMES_AS_GROUP_TAGS:
        all_pre_group_tags = all_group_tags
    else:
        for t in complete_list_of_pre_rules:
            if 'group_tag' in t:
                if t['group_tag'] not in all_pre_group_tags:
                    all_pre_group_tags.append(t['group_tag'])

    all_pre_group_tags_deduped = set(all_pre_group_tags)

    # Display the table if verbose output is enabled
    if settings.VERBOSE_OUTPUT:
        console.print(table)

    # This is the end of the PRE rule base
    # Now we return the list of created rules to the caller of this function
    return rules, all_pre_group_tags_deduped
