"""
Auxiliary utilities for PAN-OS policy testing.

This module provides utility functions for the PAN-OS policy testing tool, including
firewall initialization, menu display, and application data processing. It contains
functions for connecting to a firewall, retrieving application information, and
displaying the user interface elements.

Functions:
    _get_default_ports: Extract default ports from an application.
    et_to_dict: Convert an ElementTree element to a dictionary.
    initialize_firewall: Connect to a firewall and retrieve application information.
    display_banner: Display the application banner.
    display_menu: Display the main menu and get user selection.
"""
import sys
import os
import re
import json
from getpass import getpass
# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from rich.panel import Panel
from lib.rich_output import console
import testing.lib.user_identity as uid  # access the globals there
from panos.firewall import Firewall
import settings
import requests
from rich.status import Status

# Global variables to store firewall connection info
FIREWALL_ADDRESS = ""
FIREWALL_VSYS = ""
FIREWALL_PLATFORM = ""
FIREWALL_VERSION = ""
FIREWALL_CONTENT_VERSION = ""
FIREWALL_SERIAL = ""

# Global variable to store built-in apps
NORMALIZED_BUILT_IN_APPS = dict()

def _get_default_ports(app):
    """
    Extract default ports from an application.

    Args:
        app: Dictionary containing application data

    Returns:
        The member attribute of port, or None if not available
    """
    default = app.get("default", {})
    if not default:
        return None

    # Handle case where default is a list
    if isinstance(default, list):
        if default and isinstance(default[0], dict) and "port" in default[0]:
            port = default[0]["port"]
            if isinstance(port, dict):
                return port.get("member")
            elif isinstance(port, list) and port and isinstance(port[0], dict):
                return port[0].get("member")
        return None

    # Handle case where default is a dictionary
    port = default.get("port")
    if not port:
        return None

    # Handle case where port is a list
    if isinstance(port, list):
        if port and isinstance(port[0], dict):
            return port[0].get("member")
        return None

    # Handle case where port is a dictionary
    return port.get("member")

# Function to convert ElementTree objects to dictionaries
def et_to_dict(element):
    """
    Convert an ElementTree element to a dictionary.

    Args:
        element: ElementTree element

    Returns:
        dict: Dictionary representation of the ElementTree element
    """
    result = {}

    # Add element attributes to the dictionary
    if element.attrib:
        result.update(element.attrib)

    # Process child elements
    for child in element:
        child_dict = et_to_dict(child)

        # If the child has no children and only text, use the text as the value
        if not child_dict and child.text and child.text.strip():
            child_dict = child.text.strip()

        # Special handling for 'member' tags which should always be in a list
        if child.tag == 'member':
            if 'member' not in result:
                result['member'] = []
            result['member'].append(child_dict)
        # Handle multiple children with the same tag
        elif child.tag in result:
            # If this is the first duplicate, convert to a list
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_dict)
        else:
            result[child.tag] = child_dict

    # Add text content if it exists and there are no children
    if element.text and element.text.strip():
        if not result:
            # If there are no attributes or children, use the text as the value
            result = element.text.strip()
        else:
            # If there are attributes or children, add the text under a special key
            result['_text'] = element.text.strip()

    return result


def initialize_firewall():
    """
    Initialize connection to a PAN-OS firewall and retrieve application information.

    This function prompts the user for firewall connection details (address, VSYS, 
    username, and password), establishes a connection to the firewall, and retrieves
    information about all applications known to the firewall. It stores connection
    details and application information in global variables for use by other functions.

    Returns:
        Firewall: A connected Firewall object, or None if connection fails.
    """
    global FIREWALL_ADDRESS, FIREWALL_VSYS, FIREWALL_PLATFORM, FIREWALL_VERSION, FIREWALL_CONTENT_VERSION, FIREWALL_SERIAL, NORMALIZED_BUILT_IN_APPS

    # Prompt for firewall address
    default_addr = settings.DEFAULT_FIREWALL
    while True:
        addr = input(f"Firewall address [`{default_addr}`]: ") or default_addr
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", addr) or re.match(r"^[\w.-]+\.[a-zA-Z]{2,}$", addr):
            break
        console.print("[bold red]Invalid address[/bold red]")

    # Store the firewall address in global variable
    FIREWALL_ADDRESS = addr

    # Prompt for VSYS
    default_vsys = settings.DEFAULT_VSYS
    vsys = input(f"Firewall VSYS [`{default_vsys}`]: ") or default_vsys

    # Store the VSYS in global variable
    FIREWALL_VSYS = vsys

    # Prompt for username
    default_user = settings.DEFAULT_ADMIN_USERNAME
    if settings.USE_COOKIE:
        try:
            with open("../" + settings.COOKIE_FILENAME) as f:
                default_user = json.load(f)["admin_username"] or default_user
        except FileNotFoundError:
            pass

    while True:
        user = input(f"Username [`{default_user}`]: ") or default_user
        if re.match(r"^[a-z0-9_.-]{3,}$", user):
            break
        console.print("[bold red]Bad username[/bold red]")
    pw = getpass("Password: ")
    if not pw:
        console.print("[bold red]Empty password[/bold red]"); return None

    fw = Firewall(hostname=addr, api_username=user, api_password=pw,
                  vsys=vsys)
    fw.refresh_system_info()

    # Store firewall details in global variables
    FIREWALL_PLATFORM = fw.platform
    FIREWALL_VERSION = fw.version
    FIREWALL_CONTENT_VERSION = fw.content_version
    FIREWALL_SERIAL = fw.serial

    console.print(f"[bold green]Connected[/bold green] to {addr} "
                  f"(PLATFORM: [cyan]{fw.platform}[/cyan] PAN-OS: [cyan]{fw.version}[/cyan] CONTENT: [cyan]{fw.content_version}[/cyan] S/N: [cyan]{fw.serial}[/cyan])")

    # Retrieve all built-in applications and their attributes
    with Status(f"Retrieving all applications known to the firewall (this may take a minute)...", console=console) as status:
        built_in_apps_full = fw.op('<show><predefined><xpath>/predefined/application</xpath></predefined></show>', cmd_xml=False, xml=False)
        status.update(f"Retrieving all applications known to the firewall...[green]COMPLETED[/green]")
        if built_in_apps_full.attrib['status'] == 'success':
            apps_full = built_in_apps_full.findall(".//application/entry")
            # Convert all ElementTree objects to dictionaries
            apps_dict = [et_to_dict(app) for app in apps_full]

            # Process and normalize the application data
            for each_app in apps_dict:
                if each_app.get("subcategory") is not None:
                    app_details = {
                        "name":                     each_app.get("name"),
                        "subcategory":              each_app.get("subcategory"),
                        "category":                 each_app.get("category"),
                        "risk":                     each_app.get("risk"),
                        "tags":                     each_app.get("tags"),
                        "description":              each_app.get("description"),
                        "references":               each_app.get("references"),
                        "icon":                     each_app.get("icon").get("_text") if isinstance(each_app.get("icon"), dict) and each_app.get("icon").get("_text") else each_app.get("icon"),
                        "evasive-behavior":         each_app.get("evasive-behavior"),
                        "consume-big-bandwidth":    each_app.get("consume-big-bandwidth"),
                        "used-by-malware":          each_app.get("used-by-malware"),
                        "able-to-transfer-file":    each_app.get("able-to-transfer-file"),
                        "has-known-vulnerability":  each_app.get("has-known-vulnerability"),
                        "tunnel-other-application": each_app.get("tunnel-other-application"),
                        "prone-to-misuse":          each_app.get("prone-to-misuse"),
                        "pervasive-use":            each_app.get("pervasive-use"),
                        "default-ports":            _get_default_ports(each_app)
                    }
                    NORMALIZED_BUILT_IN_APPS[each_app.get("name")] = app_details

            console.print(f"[green]✓[/green] Retrieved information for {len(NORMALIZED_BUILT_IN_APPS)} applications")
        else:
            console.print("[bold red]Failed to retrieve application information from the firewall.[/bold red]")

    return fw

def display_banner() -> None:
    """
    Display the application banner with information about the tool's capabilities.

    This function creates and displays a formatted panel containing information about
    the PAN-OS Policy Test Tool's capabilities, including user/group mappings,
    URL filtering tests, DNS security tests, and App-ID tests.

    Returns:
        None
    """
    txt = (
        "This tool helps you test a PAN-OS security policy:\n\n"
        "• User/group ↔ IP mappings\n"
        "• URL-filtering tests\n"
        "• DNS security tests\n"
        "• App-ID tests\n"
    )
    console.print(Panel.fit(txt, title="PAN-OS Policy Test Tool", border_style="green"))


def display_menu() -> int:
    """
    Display the main menu and get user selection.

    This function displays a formatted panel containing the current testing values
    (firewall address, source IP, domain prefix, etc.) and a menu of options for
    the user to select from. It prompts the user for a choice and validates the input.

    Returns:
        int: The user's menu selection (1-10).
    """
    menu = (
        "[bold]Current values for testing:[/bold]\n"
        f" Firewall address:       [magenta]{FIREWALL_ADDRESS or 'None'} ({FIREWALL_VSYS or 'None'})[/magenta]\n"
        f" Firewall details:       [magenta]{FIREWALL_PLATFORM or 'N/A'}, sn {FIREWALL_SERIAL or 'N/A'}[/magenta]\n"
        f" Firewall version:       [magenta]{FIREWALL_VERSION or 'N/A'}, {FIREWALL_CONTENT_VERSION or 'N/A'}[/magenta]\n"
        f" Source IP address:      {f'[cyan]None[/cyan]' if not uid.SOURCE_IP_FOR_TESTING else uid.SOURCE_IP_FOR_TESTING}\n"
        f" Mapped user and groups: {f'[cyan]None[/cyan]' if not uid.MAPPED_USER else uid.MAPPED_USER + (f' ({uid.MAPPED_GROUP}' + (f', {uid.DECRYPTION_GROUP}' if uid.DECRYPTION_ENABLED and uid.DECRYPTION_GROUP else '') + ')' if uid.MAPPED_GROUP else '')}\n"
        f" Domain prefix:          {f'[cyan]None[/cyan]' if not uid.DOMAIN_PREFIX else uid.DOMAIN_PREFIX}\n"
        f" Decryption enabled:     {'Yes' if uid.DECRYPTION_ENABLED else 'No'}\n"
        "[bold]Select:[/bold]\n"
        f" 1. {f'[cyan]Set source IP address[/cyan]' if not uid.SOURCE_IP_FOR_TESTING else 'Set source IP address'}\n"
        f" 2. {f'[cyan]Set a domain prefix for all users and groups (optional)[/cyan]' if not uid.DOMAIN_PREFIX else 'Set a domain prefix for all users and groups'}\n"
        f" 3. Toggle decryption on/off\n"
        f" 4. {f'[cyan]Set user and group mapping to the source IP[/cyan]' if not (uid.MAPPED_USER and uid.MAPPED_GROUP) else 'Set user and group mapping to the source IP'}\n"
        " 5. URL filtering test (for currently mapped user & group)\n"
        " 6. URL filtering test (for all groups)\n"
        " 7. App-ID test for a single application   (for currently mapped user & group)\n"
        " 8. App-ID test for all known applications (for currently mapped user & group)\n"
        " 9. DNS security test\n"
        "10. Exit\n\n"
        "[italic yellow]Note: URL and DNS tests produce real traffic from the specified source IP,\n"
        "      while App-ID is a synthetic test.[/italic yellow]"
    )
    console.print(Panel.fit(menu, title="Policy Test Menu", border_style="blue"))
    while True:
        try:
            choice = int(input("Choice (1-10): "))
            if 1 <= choice <= 10:
                return choice
        except ValueError:
            pass
        console.print("[red]Enter a number 1-10[/red]")
