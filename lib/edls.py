"""
Functions for creating and managing External Dynamic Lists (EDLs) in PAN-OS.

This module provides functionality to:

- Create and configure EDLs from CSV configuration files
- Support different EDL types (IP, URL, Domain, etc.)
- Configure EDL update schedules and certificate profiles
- Handle environment-specific EDL source URLs
- Deploy EDLs to PAN-OS devices using multi-config API calls
"""

import settings
from lib.auxiliary_functions import parse_metadata_from_csv, execute_multi_config_api_call
from panos.objects          import Edl
from rich.console import Console
from rich.table import Table
from rich.text import Text



def create_edls(edl_container, panos_device, target_env):
    """
    Creates External Dynamic Lists (EDLs) in the given DeviceGroup or VSYS object.
    Uses the target environment to replace placeholders in the EDL source URLs.

    Args:
        edl_container: A container object from the `panos` library that holds EDL
            configurations to be added to the PAN-OS device.
        panos_device: A `panos` device object representing the target PAN-OS device where
            the EDLs will be deployed.
        target_env: A string representing the target environment that can be used to replace
            placeholders in the EDL source URLs during processing.

    Raises:
        PanXapiError: Raised if there is an issue while deploying the staged EDLs via the
            PAN-OS API. The process will terminate with a detailed error message.
    """
    panos_device.add(edl_container)
    edls = parse_metadata_from_csv('EDLs', settings.EDLS_FILENAME)

    console = Console()
    console.print("Staging External Dynamic Lists (EDLs):")

    # Create a table for EDLs
    table = Table(title="External Dynamic Lists (EDLs)", highlight=False)
    table.add_column("Name", style="green")
    table.add_column("Source", style="cyan")
    table.add_column("Repeat", style="magenta")

    action_id = 1
    multi_config_xml = '<multi-config>'

    for edl in edls:
        # Fix for Excel dropping the leading 0 when the input CSV is edited
        if len(edl['Repeat At']) == 1:
            repeat_at = '0' + edl['Repeat At']
        else:
            repeat_at = edl['Repeat At']

        # Check if the cert profile is defined and setting it to None if not

        if len(edl['Certificate Profile']) == 0:
            certificate_profile = None
            username            = None
            password            = None
        else:
            certificate_profile = edl['Certificate Profile']
            username            = edl['Username']
            password            = edl['Password']

        edl_source = edl['Source']

        if "<target_environment>" in edl_source:
            prefix, suffix = edl_source.split("<target_environment>", 1)
            # build a Text object with mixed styles
            source_text = Text(prefix)
            source_text.append(target_env, style="bold yellow")
            source_text.append(suffix)
            # and update the actual URL for the API call
            edl_source = prefix + target_env + suffix
        else:
            source_text = Text(edl_source, style="cyan")

        # Add a row to the table
        table.add_row(
            edl['Name'],
            source_text,
            edl['Repeat']
        )

        edl_object = Edl(name=edl['Name'], edl_type=edl['Type'], repeat=edl['Repeat'],
                          repeat_at=repeat_at, source=edl_source,
                          username=username, password=password,
                          certificate_profile=certificate_profile,
                          description=edl['Description'])

        edl_container.add(edl_object)

        multi_config_xml += f'<edit id="{action_id}" xpath="{edl_object.xpath()}">{edl_object.element_str().decode()}</edit>'
        action_id += 1

    multi_config_xml += '</multi-config>'

    # Display the table
    console.print(table)

    execute_multi_config_api_call(panos_device, multi_config_xml, "Creating the staged EDLs...", 0)
