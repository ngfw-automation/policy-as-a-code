"""
Functions for importing custom objects into PAN-OS devices.

This module provides functionality to:

- Import custom response pages with Jinja2 templating support
- Import custom signatures for applications, vulnerabilities, and spyware
- Handle environment-specific configurations for different deployment targets
- Process and normalize XML content for proper PAN-OS integration
"""

import os
import requests
import json
import yaml
import xml.etree.ElementTree as ET
from rich import print

import  settings
import  urllib3
from    urllib3.exceptions     import InsecureRequestWarning
from    panos.panorama         import Panorama
from    lib.auxiliary_functions import execute_multi_config_api_call
from    tqdm                   import tqdm
from    jinja2                 import Environment, FileSystemLoader


def import_custom_response_pages(target, panos_device, target_env):
    """
    Imports Jinja2-rendered custom response pages into a PAN-OS device using templates and configuration files.
    """
    response_pages = {
        "Antivirus Anti-Spyware Block Page": "virus-block-page",
        "Application Block Page": "application-block-page",
        "File Blocking Block Page": "file-block-page",
        "File Blocking Continue Page": "file-block-continue-page",
        "SSL Certificate Errors Notify Page": "ssl-cert-status-page",
        "URL Filtering and Category Match Block Page": "url-block-page",
        "URL Filtering Continue and Override Page": "url-coach-text"
    }

    urllib3.disable_warnings(InsecureRequestWarning)
    print("Importing custom response pages...")

    # Resolve the folder path for the selected environment
    folder = settings.CUSTOM_RESPONSE_PAGES_FOLDER
    if "<target_environment>" in folder:
        folder = folder.replace("<target_environment>", target_env)
    if settings.VERBOSE_OUTPUT:
        print(f"The target environment is '{target_env}'")
        print(f"Using the folder: '{folder}'")

    # Set system setting target for the import operation
    print(f"Setting target for response pages import operation...", end="")
    if isinstance(panos_device, Panorama):
        target_template = target.name  # Get template name for Panorama
        op_result = panos_device.op(
            cmd=f"<set><system><setting><target><template>{target_template}</template></target></setting></system></set>",
            cmd_xml=False)
    else:
        target_vsys = target.name  # Get VSYS name for firewall
        op_result = panos_device.op(
            cmd=f"<set><system><setting><target-vsys>{target_vsys}</target-vsys></setting></system></set>",
            cmd_xml=False)

    # Extract and print the operation result status
    status = op_result.get('status')
    result = op_result.find('result').text
    print(f"{status} ({result})")

    # Initialize Jinja2 environment with the template folder
    env = Environment(loader=FileSystemLoader(os.path.join(folder, "templates")))

    # Load shared config for common values (firm name, CSS, timestamp message, etc.)
    shared_config_path = os.path.join(folder, "shared.yaml")
    with open(shared_config_path, 'r', encoding="utf-8") as sf:
        shared = yaml.safe_load(sf)

    # Iterate over all defined response page types
    for page_name, page_type in tqdm(response_pages.items() or [], desc="Uploading custom response pages", ncols=100, colour='white'):
        template_file = f"{page_type}.html.j2"  # Template filename
        config_file = os.path.join(folder, "configs", f"{page_type}.yaml")  # YAML config path

        # Check if both template and config exist
        if os.path.exists(os.path.join(folder, "templates", template_file)) and os.path.exists(config_file):
            # Load template and config
            template = env.get_template(template_file)
            with open(config_file, 'r', encoding="utf-8") as cf:
                page_config = yaml.safe_load(cf)

            # Merge shared config with page-specific config
            context = {**shared, **page_config}

            # Render HTML from merged context
            rendered_html = template.render(**context)

            # Upload rendered HTML to PAN-OS
            files = {'file': (page_type, rendered_html)}
            import_page_url = f"https://{panos_device.hostname}/api/?type=import&category={page_type}&key={panos_device.api_key}"
            try:
                response = requests.post(import_page_url, files=files, verify=False)
                op_result = ET.fromstring(response.text)
                status = op_result.get('status')
                result = op_result.find('result').text
                tqdm.write(f"Uploaded [{page_name}]...{status}")
            except Exception as e:
                tqdm.write(f"Failed to upload the page [{page_name}]")
                if settings.DEBUG_OUTPUT:
                    tqdm.write(str(e))
                continue
        else:
            # Skip if template or config is missing
            tqdm.write(f"Template or config missing for [{page_name}] → Expected: templates/{template_file}, configs/{page_type}.yaml")


def import_custom_signatures(target, panos_device):
    """
    Imports custom signatures into a given PAN-OS device by reading signature files
    from the disk, cleaning them, and staging them for deployment via a multi-config
    API call.

    This function processes different types of custom signatures (e.g., application,
    vulnerability, spyware) stored on disk, prepares them for integration into
    a PAN-OS device, and executes the API call to upload them.

    Args:
        target: VSYS or Template object where the custom signatures will be imported.
        panos_device: Panorama or Firewall object representing the target device.

    """
    panos_device.add(target)
    # define signature location in PAN-OS and on disk
    signature_location = {
        "application":  {
            "relative_xpath":   "/application",
            "folder":           settings.CUSTOM_APPLICATION_SIGNATURES_FOLDER
        },
        "vulnerability":    {
            "relative_xpath":   "/threats/vulnerability",
            "folder":           settings.CUSTOM_VULNERABILITY_SIGNATURES_FOLDER
        },
        "spyware":          {
            "relative_xpath":   "/threats/spyware",
            "folder":           settings.CUSTOM_SPYWARE_SIGNATURES_FOLDER
        }
    }

    action_id = 1
    multi_config_xml = '<multi-config>'

    for signature_type in signature_location.items():
        print(f"Staging {signature_type[0]} signatures for import:")
        for filename in os.listdir(signature_location[signature_type[0]]["folder"]):
            if filename.endswith(".xml"):
                file_path = os.path.join(signature_location[signature_type[0]]["folder"], filename)
                if settings.VERBOSE_OUTPUT: print(f"\t- {filename}")
                xpath = target.xpath() + signature_location[signature_type[0]]['relative_xpath']

                # read the file from disk and normalize it
                with open(file_path, 'r') as file:
                    signature_xml = file.read()

                # Parse the XML and find the <entry> tag
                tree = ET.fromstring(signature_xml)
                entry_element = tree.find(".//entry")  # Find the <entry> tag

                # Convert the <entry> element to a string
                cleaned_xml = ET.tostring(entry_element, encoding='unicode', method='xml')
                # Strip any trailing newlines or extra spaces
                cleaned_xml = cleaned_xml.strip()

                # stage a sub-operation in the multi-config
                multi_config_xml += f'<set id="{action_id}" xpath="{xpath}">{cleaned_xml}</set>'
                action_id += 1

    multi_config_xml += '</multi-config>'

    execute_multi_config_api_call(panos_device, multi_config_xml, "Importing the staged signatures...", 0)
    return
