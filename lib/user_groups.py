"""
Functions for managing user groups in PAN-OS and Active Directory.

This module provides functionality to:

- Create local user groups on PAN-OS firewalls based on policy requirements
- Generate groups for managed application and URL categories
- Create special groups for decryption policy exceptions
- List all user groups referenced in security policies
- Create required groups in Active Directory via LDAP
- Verify existing groups in Active Directory
- Support automated group creation with appropriate permissions
"""

import panos.device
import settings
import os
import ssl
from getpass    import getpass
from ldap3      import Server, Connection, ALL, Tls, LEVEL, AUTO_BIND_DEFAULT
from rich import print


def add_user_groups(target_fw, app_categories, url_categories):
    # Creation of local user groups on the firewalls
    if settings.CREATE_GROUPS_USED_IN_POLICY_FIREWALL:
        print("\t\tUser groups  - for managed APP categories...")
        for category in app_categories:
            if (category["Action"].lower() == settings.APP_ACTION_MANAGE or category["Action"].lower() == settings.APP_ACTION_ALERT) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
                target_fw.add(panos.device.LocalUserDatabaseGroup(name=category["UserID"])).apply()
        print("\t\tUser groups  - for managed URL categories...")
        for category in url_categories:
            if (category["Action"].lower() == settings.APP_ACTION_MANAGE or category["Action"].lower() == settings.APP_ACTION_ALERT) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
                target_fw.add(panos.device.LocalUserDatabaseGroup(name=category["UserID"])).apply()

        # Groups for decryption (names defined in Settings)
        target_fw.add(panos.device.LocalUserDatabaseGroup(name=settings.GRP_PREDEFINED('grp_tls_d_exception'))).apply()
        target_fw.add(panos.device.LocalUserDatabaseGroup(name=settings.GRP_PREDEFINED('grp_tls_d_decrypt'))).apply()


def list_user_groups(target_fw, app_categories, url_categories):
    # Creation of local user groups on the firewalls

    print("\nThe user groups listed below have been referenced in the policy "
          "as per the requirements set for APP/URL categories. \nTherefore they must be "
          "provided by the UserID subsystem \n(i.e. be provided via AD integration or be "
          "created in the Local User Database):\n\n")

    groups_for_all_managed_categories = list()
    for category in app_categories:
        # if (category["Action"].lower() == settings.app_action_manage or category["Action"].lower() == settings.app_action_alert) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            groups_for_all_managed_categories.append(category["UserID"])

    for category in url_categories:
        # if (category["Action"].lower() == settings.app_action_manage or category["Action"].lower() == settings.app_action_alert) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            groups_for_all_managed_categories.append(category["UserID"])

    # Hard-coded groups for decryption (names defined in Settings)
    for group_name in settings.GRP_PREDEFINED.values():
        groups_for_all_managed_categories.append(group_name)

    # Deduplicate the list
    groups_for_all_managed_categories = list(dict.fromkeys(groups_for_all_managed_categories))

    # Print the list
    for category in groups_for_all_managed_categories:
        print(category)

    print('\n\nEnd of the list')

    return groups_for_all_managed_categories


def create_user_groups_in_ad(groups_to_be_created):
    """
    This function takes a list of groups and attempts to create them under a given OU defined in settings.
    :param groups_to_be_created: list of group names that need to be created (unless they already exist)
    :return:
    """
    existing_groups = list()

    if settings.CREATE_AD_GROUPS:

        print('Creation of the groups in the AD (unless they already exist)...')

        ldap_user_account = input('\nEnter a username of administrator who has permissions to create groups in the target OU:')
        ldap_password     = getpass('Enter password:')

        # Establishing LDAP server address (we grap user's logon server (DC) and domain name)
        ldap_server = os.environ.get("LOGONSERVER").split('\\')[-1]
        ldap_server_dns_domain = os.environ.get("USERDNSDOMAIN")
        ldap_server_domain = os.environ.get("USERDOMAIN")
        ldap_server_fqdn = ldap_server.lower() + '.' + ldap_server_dns_domain.lower()

        print(f'\nConnecting to the LDAP server "{ldap_server_fqdn}" as "{ldap_user_account.lower()}"...', end='')

        tls_configuration = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1_2)
        serv = Server(ldap_server_fqdn, use_ssl=True, get_info=ALL, tls=tls_configuration)
        conn = Connection(serv, user=f"{ldap_server_domain}\\{ldap_user_account}", password=ldap_password, auto_bind=AUTO_BIND_DEFAULT)

        try:
            conn.open()
            conn.bind()
        except:
            print(conn.result['description'], conn.result['message'])
            print('Check your credentials and try again!')
        else:
            print(conn.result['description'], conn.result['message'])
            print('\nNow we are going to check if all required groups already exist, and if they do not exist, we create them from scratch.')
            print(f'We are looking only for Universal Security Groups in [{settings.AD_OU_CANONICAL_NAME}].')
            conn.search(search_base=settings.AD_OU_CANONICAL_NAME, search_filter='(&(objectClass=Group)(groupType=-2147483640))', search_scope=LEVEL, attributes=['cn'])

            if conn.result['description'] == 'success':

                print('\nGroups that already exist in the AD:')
                for entry in conn.entries:
                    print(f'\t> {entry.cn.value}')
                    existing_groups.append(entry.cn.value)
                existing_groups.sort()

                print('\nGroups that must exist:')
                groups_to_be_created.sort()
                for entry in groups_to_be_created:
                    print(f'\t> {entry}')

                print('\nCreating groups that are missing:')
                for entry in groups_to_be_created:
                    if entry not in existing_groups:
                        print(f'\t+ {entry} - ', end='')
                        dn_of_the_group_to_be_created = 'CN=' + entry + ',' + settings.AD_OU_CANONICAL_NAME
                        conn.add(dn=dn_of_the_group_to_be_created, object_class='Group', attributes={'groupType': '-2147483640', 'sAMAccountName': entry, 'description': 'Gen2 firewall policy group (this group is auto-generated - it MUST NOT be renamed or moved to a different OU)'})
                        print(conn.result['description'])

                print('\nCreation of groups completed')

            else:
                print('Search was not successful:', conn.result['description'], conn.result['message'])
            conn.unbind()

    else:
        print('Skipping the creation of groups in the AD (enable this in Settings if required)...')
