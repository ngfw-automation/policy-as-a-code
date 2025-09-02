"""
Functions for creating and managing security profile groups in PAN-OS.

This module provides functionality to:
- Create predefined security profile groups with specific security profiles
- Configure different profile groups for various use cases (managed URLs, apps, risky content)
- Combine multiple security profiles (antivirus, anti-spyware, vulnerability, URL filtering, etc.)
- Create specialized profile groups for different risk levels
- Deploy profile groups to PAN-OS devices using multi-config API calls
"""

import settings
import sys
from panos.objects import SecurityProfileGroup
from lib.auxiliary_functions import execute_multi_config_api_call
from rich import print


def create_security_profile_groups(profile_container, panos_device):
    """
    Adds predefined security profile groups to the specified profile container.

    Args:
        profile_container: The container object where the security profile groups will be added (device group of firewall object).
        panorama: Optional; The Panorama object if the profiles are to be added on a Panorama device.

    Raises:
        Exception: If there is an error during the API call to add the profiles.
    """
    print("Staging security profile groups:")
    profile_container.add(SecurityProfileGroup(name='PG-managed-urls',
                                               virus=settings.SP_VIRUS,
                                               spyware=settings.SP_SPYWARE,
                                               vulnerability=settings.SP_VULNR,
                                               url_filtering=settings.SP_URL_CTRLD,
                                               file_blocking=settings.SP_FILE,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-apps-trusted',
                                               url_filtering=settings.SP_URL_CTRLD,
                                               file_blocking=settings.SP_FILE_LOG_ONLY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-managed-urls-risky',
                                               virus=settings.SP_VIRUS_RISKY,
                                               spyware=settings.SP_SPYWARE_RISKY,
                                               vulnerability=settings.SP_VULNR_RISKY,
                                               url_filtering=settings.SP_URL_CTRLD_RISKY,
                                               file_blocking=settings.SP_FILE_RISKY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-managed-urls-very-risky',
                                               virus=settings.SP_VIRUS_RISKY,
                                               spyware=settings.SP_SPYWARE_RISKY,
                                               vulnerability=settings.SP_VULNR_RISKY,
                                               url_filtering=settings.SP_URL_CTRLD_RISKY,
                                               file_blocking=settings.SP_FILE_RISKY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-managed-urls-allowed-exe',
                                               virus=settings.SP_VIRUS,
                                               spyware=settings.SP_SPYWARE,
                                               vulnerability=settings.SP_VULNR,
                                               url_filtering=settings.SP_URL_CTRLD,
                                               file_blocking=settings.SP_FILE_ALLOW_EXE,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-non-managed-urls',
                                               virus=settings.SP_VIRUS,
                                               spyware=settings.SP_SPYWARE,
                                               vulnerability=settings.SP_VULNR,
                                               url_filtering=settings.SP_URL_NON_CTRLD,
                                               file_blocking=settings.SP_FILE,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-non-managed-urls-risky',
                                               virus=settings.SP_VIRUS_RISKY,
                                               spyware=settings.SP_SPYWARE_RISKY,
                                               vulnerability=settings.SP_VULNR_RISKY,
                                               url_filtering=settings.SP_URL_NON_CTRLD_RISKY,
                                               file_blocking=settings.SP_FILE_RISKY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))

    profile_container.add(SecurityProfileGroup(name='PG-apps-regular',
                                               virus=settings.SP_VIRUS,
                                               spyware=settings.SP_SPYWARE,
                                               vulnerability=settings.SP_VULNR,
                                               url_filtering=settings.SP_URL_CTRLD_APPS,
                                               file_blocking=settings.SP_FILE,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-apps-risky',
                                               virus=settings.SP_VIRUS_RISKY,
                                               spyware=settings.SP_SPYWARE_RISKY,
                                               vulnerability=settings.SP_VULNR_RISKY,
                                               url_filtering=settings.SP_URL_CTRLD_APPS,
                                               file_blocking=settings.SP_FILE_RISKY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))
    profile_container.add(SecurityProfileGroup(name='PG-apps-allowed-exe',
                                               virus=settings.SP_VIRUS,
                                               spyware=settings.SP_SPYWARE,
                                               vulnerability=settings.SP_VULNR,
                                               url_filtering=settings.SP_URL_CTRLD_APPS,
                                               file_blocking=settings.SP_FILE_ALLOW_EXE,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))

    profile_container.add(SecurityProfileGroup(name='PG-break-glass',
                                               url_filtering=settings.SP_URL_CTRLD_RISKY,
                                               file_blocking=settings.SP_FILE_LOG_ONLY,
                                               data_filtering=settings.SP_DATA_FILTERING,
                                               wildfire_analysis=settings.SP_WILDFIRE))

    profile_group_names = ["PG-managed-urls",
                           "PG-apps-trusted",
                           "PG-managed-urls-risky",
                           "PG-managed-urls-very-risky",
                           "PG-managed-urls-allowed-exe",
                           "PG-non-managed-urls",
                           "PG-non-managed-urls-risky",
                           "PG-apps-regular",
                           "PG-apps-risky",
                           "PG-apps-allowed-exe",
                           "PG-break-glass"]

    action_id = 1
    multi_config_xml = '<multi-config>'
    for profile_group_name in profile_group_names:
        print(f"\t{profile_group_name}")
        obj_element = profile_container.find(profile_group_name, SecurityProfileGroup).element_str().decode()
        obj_xpath   = profile_container.xpath() + f"/profile-group"
        multi_config_xml += f'<set id="{action_id}" xpath="{obj_xpath}">{obj_element}</set>'
        action_id += 1

    multi_config_xml += '</multi-config>'
    execute_multi_config_api_call(panos_device, multi_config_xml, 'Creating all staged security profile groups...', 0)
