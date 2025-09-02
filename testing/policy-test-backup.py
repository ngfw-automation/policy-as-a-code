"""
Policy Testing Module for Next-Generation Firewall.

This module provides comprehensive testing capabilities for network security policies
implemented on PAN-OS firewalls. It includes functionality for testing URL filtering,
DNS security, user-to-IP mapping, and other security features.

The module allows administrators to:
- Connect to and initialize a PAN-OS firewall
- Map users to IP addresses and security groups
- Test URL filtering policies across different user groups
- Test DNS security features including DNS-over-TLS and DNS-over-HTTPS
- Verify policy enforcement for different network scenarios

This tool is designed to be run interactively, presenting a menu of testing options
to the user and displaying results in a formatted, easy-to-read manner.
"""

import sys
import re
import os
import json
import csv
import base64
import datetime
from getpass import getpass
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import requests

import ssl
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from bs4 import BeautifulSoup
from typing import Dict, List


# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.rich_output import console
from panos.firewall import Firewall
import settings
from rich.panel import Panel
from rich.table import Table, Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from lib.auxiliary_functions import parse_metadata_from_csv


# Global variables for testing
SOURCE_IP_FOR_TESTING = "192.168.1.100"
DOMAIN_PREFIX = ""
DECRYPTION_GROUP = "ug-decryption"


# fw.test_security_policy_match(source="192.168.51.10",destination="1.1.1.1", port=443, protocol=6, application="google-base", from_zone="INSIDE", to_zone="OUTSIDE", show_all=False)


def initialize_firewall():
    """Initialize a connection to the firewall with user-provided credentials.

    This function prompts the user for firewall connection details and establishes
    a connection to the PAN-OS firewall. It validates input formats and provides
    appropriate error messages for invalid inputs.

    Args:
        None

    Returns:
        int: 1 if there was an error during initialization, None otherwise

    Note:
        Prompts the user for:
        - Firewall address (IPv4 or FQDN)
        - Admin username
        - Admin password
        - Vsys name

        Validates the firewall address format using regex patterns for both IPv4 and FQDN.
        For IPv4, also validates that each octet is between 0-255.
    """
    # Get credentials
    #
    # Read the default firewall address from Settings
    default_panos_address = settings.DEFAULT_FIREWALL

    # Prompt for firewall address with validation
    while True:
        panos_address = input(f'Enter firewall address [`{default_panos_address}`]: ') or default_panos_address

        # Validate IPv4 address format
        ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        ipv4_match = re.match(ipv4_pattern, panos_address)

        # Validate FQDN format
        fqdn_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        fqdn_match = re.match(fqdn_pattern, panos_address)

        if ipv4_match:
            # Validate each octet is between 0-255
            valid_ip = True
            for octet in ipv4_match.groups():
                if int(octet) > 255:
                    valid_ip = False
                    break

            if valid_ip:
                break
            else:
                console.print("[bold red]Error:[/bold red] Invalid IPv4 address. Each octet must be between 0-255.")
        elif fqdn_match:
            break
        else:
            console.print("[bold red]Error:[/bold red] Invalid address format. Please enter a valid IPv4 address or FQDN.")

    # Read the default admin username from Settings
    default_admin_username = settings.DEFAULT_ADMIN_USERNAME
    # override it with username from the Cookies file (if the feature is enabled)
    if settings.USE_COOKIE:
        try:
            with open("../" + settings.COOKIE_FILENAME, 'r') as f:
                cookie = json.load(f)
            if cookie['admin_username'] is not None:
                default_admin_username = cookie['admin_username']
        except FileNotFoundError:
            # if there is no cookie file we create it with a default value
            cookie = json.dumps({"admin_username": settings.DEFAULT_ADMIN_USERNAME}, indent=4)
            with open(settings.COOKIE_FILENAME, 'w') as f:
                f.write(cookie)

    # Prompt the admin suggesting a default value
    while True:
        admin_username = input(f'Enter username [`{default_admin_username}`]: ').lower() or default_admin_username
        # Validate username: only allow alphanumeric characters, underscore, and dot
        if not re.match(r'^[a-z0-9_.-]+$', admin_username):
            console.print(
                "[bold red]Error:[/bold red] Username can only contain lowercase letters, numbers, underscores, dashes, and dots.")
            continue
        # Ensure minimum length
        if len(admin_username) < 3:
            console.print("[bold red]Error:[/bold red] Username must be at least 3 characters long.")
            continue
        break

    admin_password = getpass("Enter password: ")
    # Validate password is not empty
    if not admin_password:
        console.print("[bold red]Error:[/bold red] Password cannot be empty.")
        return 1

    # Read the default vsys name from Settings
    default_vsys = settings.DEFAULT_VSYS

    # Prompt for vsys name
    vsys_name = input(f'Enter vsys name [`{default_vsys}`]: ') or default_vsys

    panos_device = Firewall(hostname=panos_address, api_username=admin_username, api_password=admin_password, vsys=vsys_name)
    panos_device.refresh_system_info()
    console.print(f"\n[bold green]Successfully connected to [cyan]{panos_address}[/cyan] (PLATFORM: [cyan]{panos_device.platform}[/cyan] PAN-OS: [cyan]{panos_device.version}[/cyan] CONTENT: [cyan]{panos_device.content_version}[/cyan] VSYS: [cyan]{panos_device.vsys}[/cyan])[/bold green]")

    # return the device object
    return panos_device


def map_user_to_ip_and_group(panos_device, ip_address, group_name, user_name="user1", all_groups=None, suppress_output=False, add_decryption_group=False, skip_group_name=False):
    """
    Maps a user to an IP address and adds the user to a group using the User-ID API.

    This function sends an API request to the PAN-OS device to:
    1. Map the user to the specified IP address
    2. Add the user to the specified group (unless skip_group_name is True)
    3. Create empty entries for all other groups if all_groups is provided
    4. If add_decryption_group is True and DECRYPTION_GROUP is set, also add the user to the decryption group

    If a domain prefix is set, it will be added to all user and group names in the format <domain>\\<user|group name>.

    Args:
        panos_device: PanOS device object
        ip_address: IP address to map the user to
        group_name: Group name to add the user to (ignored if skip_group_name is True)
        user_name: User name to map (default: "user1")
        all_groups: List of all group names (default: None)
        suppress_output: Whether to suppress console output (default: False)
        add_decryption_group: Whether to add the user to the decryption group (default: False)
        skip_group_name: Whether to skip adding the user to the specified group_name (default: False)

    Returns:
        bool: True if successful, False otherwise
    """
    global DOMAIN_PREFIX, DECRYPTION_GROUP

    # Suppress InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    if not panos_device:
        console.print("[bold red]Error:[/bold red] No PAN-OS device connection available.")
        return False

    # Add domain prefix to user and group names if set
    formatted_user_name = f"{DOMAIN_PREFIX}\\{user_name}" if DOMAIN_PREFIX else user_name

    # Only format group_name if it's not None and we're not skipping it
    formatted_group_name = None
    if group_name is not None:
        formatted_group_name = f"{DOMAIN_PREFIX}\\{group_name}" if DOMAIN_PREFIX else group_name

    # Start building the XML data
    xml_groups = ""
    if not skip_group_name and formatted_group_name is not None:
        xml_groups = f"""	<entry name="{formatted_group_name}">
		<members>
			<entry name="{formatted_user_name}"/>
		</members>
	</entry>
"""

    # Add the decryption group if requested and it's set
    if add_decryption_group and DECRYPTION_GROUP:
        formatted_decryption_group = f"{DOMAIN_PREFIX}\\{DECRYPTION_GROUP}" if DOMAIN_PREFIX else DECRYPTION_GROUP
        xml_groups += f"""	<entry name="{formatted_decryption_group}">
		<members>
			<entry name="{formatted_user_name}"/>
		</members>
	</entry>
"""

    # Add empty entries for all other groups if provided
    if all_groups:
        for group in all_groups:
            if group != group_name and (not DECRYPTION_GROUP or group != DECRYPTION_GROUP):
                formatted_other_group = f"{DOMAIN_PREFIX}\\{group}" if DOMAIN_PREFIX else group
                xml_groups += f"""	<entry name="{formatted_other_group}">
		<members>
		</members>
	</entry>
"""

    # Construct the complete XML data
    xml_data = f"""<uid-message>
 <version>1.0</version>
 <type>update</type>
 <payload>
	<login>
		<entry name="{formatted_user_name}" ip="{ip_address}" timeout="20"/>
	</login>
 <groups>
{xml_groups} </groups>
 </payload>
</uid-message>"""

    # Construct the API URL
    api_url = f"https://{panos_device.hostname}/api/"

    # Set up the headers with the API key
    headers = {
        "X-PAN-KEY": panos_device.api_key
    }

    # Set up the parameters
    params = {
        "type": "user-id",
        "cmd": xml_data
    }

    try:
        # Send the API request
        # Note: verify=False is used to bypass SSL certificate verification
        # In production, you should use proper certificate validation
        response = requests.post(api_url, headers=headers, params=params, verify=False)

        # Check if the request was successful
        if response.status_code == 200:
            if not suppress_output:
                if skip_group_name or formatted_group_name is None:
                    console.print(f"[bold green]Successfully mapped user [cyan]{formatted_user_name}[/cyan] to IP [cyan]{ip_address}[/cyan][/bold green]")
                else:
                    console.print(f"[bold green]Successfully mapped user [cyan]{formatted_user_name}[/cyan] to IP [cyan]{ip_address}[/cyan] and added to group [cyan]{formatted_group_name}[/cyan][/bold green]")
            return True
        else:
            if not suppress_output:
                console.print(f"[bold red]Error:[/bold red] API request failed with status code {response.status_code}")
                console.print(f"Response: {response.text}")
            return False
    except Exception as e:
        if not suppress_output:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return False


def create_user_group_mapping(panos_device=None):
    """Create a user and group mapping.

    This function creates a mapping between a user, IP address, and security group.
    It uses the global SOURCE_IP_FOR_TESTING variable as the source IP address.

    Args:
        panos_device: Optional PanOS device object. If None, an error message is displayed.

    Returns:
        None

    Note:
        If SOURCE_IP_FOR_TESTING is not set, it suggests the operator to set it first 
        using menu option #1, and returns to the main menu.

        This function prompts the user for:
        - Group name
        - Username (optional, defaults to "user1")

        Then calls map_user_to_ip_and_group to create the mapping using 
        SOURCE_IP_FOR_TESTING as the IP address.
    """
    global SOURCE_IP_FOR_TESTING

    console.print("[bold green]Creating user and group mapping...[/bold green]")

    if not panos_device:
        console.print("[bold red]Error:[/bold red] No PAN-OS device connection available.")
        input("\nPress Enter to return to the main menu...")
        return

    # Check if SOURCE_IP_FOR_TESTING is set
    if not SOURCE_IP_FOR_TESTING:
        console.print("[bold red]Error:[/bold red] Source IP for testing is not set.")
        console.print("[bold yellow]Please use menu option #1 to set the source IP first.[/bold yellow]")
        input("\nPress Enter to return to the main menu...")
        return

    console.print(f"Using source IP: [cyan]{SOURCE_IP_FOR_TESTING}[/cyan]")

    # Prompt for group name
    group_name = input('Enter group name: ')
    if not group_name:
        console.print("[bold red]Error:[/bold red] Group name cannot be empty.")
        input("\nPress Enter to return to the main menu...")
        return

    # Prompt for username (optional)
    user_name = input('Enter user name [user1]: ') or "user1"

    # Call the function to map the user to the IP and add to the group
    map_user_to_ip_and_group(panos_device, SOURCE_IP_FOR_TESTING, group_name, user_name)

    input("\nPress Enter to return to the main menu...")


def test_url(url, protocol):
    """
    Tests a given URL over HTTP or HTTPS and determines its accessibility status.

    This function performs the following:
    - Connects to the specified URL.
    - Interprets HTTP responses to detect if access is allowed, blocked, or paused by the firewall.

    Args:
        url (str): The URL (hostname + path) to test, e.g., 'example.com/page'.
        protocol (str): The protocol to use, either 'http' or 'https'.

    Returns:
        Tuple[str, str]: A tuple containing:
            - status (str): One of 'Allowed', 'Paused', 'Blocked', or 'unknown'.
            - result (str): Additional detail including status code and page content.
    """
    result = 'unknown'
    status = 'unknown'

    # Safely quote the full URL
    quoted_url = quote(f'{protocol.lower()}://{url}', safe=':"?&=\'<>/[]@')
    req = Request(quoted_url)

    try:
        # Handle HTTPS cert ignoring if needed
        if protocol.lower() == 'https':
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            response = urlopen(req, timeout=20, context=ctx)
        else:
            response = urlopen(req, timeout=20)

        # Decode and parse the HTML
        charset = response.headers.get_content_charset() or 'utf-8'
        raw_response = response.read().decode(charset)
        status_code = response.status
        soup = BeautifulSoup(raw_response, "html.parser")
        title = soup.title.string if soup.title else "No title"

        # Identify special Palo Alto test page
        if title == 'Palo Alto Networks URL filtering - Test A Site' and soup.find('h1'):
            result = f"{status_code} :: {soup.find('h1').string}"
        else:
            result = f"{status_code} :: {title}"

        # Determine final status
        if status_code == 200:
            if title == "Web Page Blocked":
                status = "Paused"  # This is the disclaimer page with "Continue" button
            else:
                status = "Allowed"

        response.close()

    except HTTPError as error:
        if error.code == 503:
            charset = error.headers.get_content_charset() or 'utf-8'
            raw_response = error.read().decode(charset)
            soup = BeautifulSoup(raw_response, "html.parser")
            if soup.title and soup.find('h1'):
                result = f"{error.code} :: {soup.title.string} ::: {soup.find('h1').string.upper()}"
                if soup.title.string == "Web Page Blocked":
                    status = "Blocked"
            else:
                result = f"{error.code} :: Service Unavailable"
                status = "Blocked"
        else:
            result = f"{error.code} :: {error.reason}"
    except URLError as error:
        result = str(error.reason)
    except TimeoutError:
        result = 'request timed out'
    except Exception as e:
        result = f'error: {str(e)}'

    return status, result


def test_url_filtering(panos_device=None):
    """Test URL filtering by making HTTP/HTTPS requests to a list of URLs.

    This function tests URL filtering policies by sending HTTP/HTTPS requests to a 
    predefined list of URLs and analyzing the responses to determine if access is 
    allowed, blocked, or paused by the firewall.

    Args:
        panos_device: Optional PanOS device object. Not directly used in this function
                      but included for consistency with other test functions.

    Returns:
        None

    Note:
        This function:
        1. Reads URLs from the file specified in settings.TEST_URLS_FILENAME
        2. Creates a Rich table to display the results
        3. Uses a progress bar to show progress as URLs are tested
        4. Tests each URL and displays the results in the table
        5. Adds background color to cells based on "Allowed" or "Blocked" status
        6. Highlights rows with "malicious" categories in light red background
    """
    console.print("[bold green]Testing URL filtering...[/bold green]")

    # Read URLs from file
    urls_data = parse_metadata_from_csv("URLs", "../" + settings.TEST_URLS_FILENAME, suppress_output=True)

    if not urls_data:
        console.print(f"[bold red]Error:[/bold red] No URLs found in {settings.TEST_URLS_FILENAME}")
        input("\nPress Enter to return to the main menu...")
        return

    # Create a table for results
    table = Table(title="URL Filtering Test Results")
    table.add_column("Protocol", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Comment", style="yellow")
    table.add_column("Result")

    # Set up progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        # Create a task for the progress bar
        task = progress.add_task("[cyan]Testing URLs...", total=len(urls_data))

        # Process each URL
        for entry in urls_data:
            # Get URL and protocol
            url = entry.get('URL', '')
            protocol = entry.get('Protocol', '')
            comment = entry.get('Comment', '')

            if not url or not protocol:
                progress.update(task, advance=1)
                continue

            # Test the URL
            try:
                status, detailed_result = test_url(url, protocol)
            except Exception as e:
                status = "Error"
                detailed_result = f"Error: {str(e)}"

            # Determine row style based on "malicious" comment
            row_style = None
            if comment.lower() == "malicious":
                row_style = "on red"

            # Determine result style based on status
            if status == "Allowed":
                result_style = "on green"
            elif status == "Blocked":
                result_style = "on red"
            elif status == "Paused":
                result_style = "on yellow"
            else:
                result_style = None

            # Add to table with appropriate styling
            if row_style:
                table.add_row(
                    Text(protocol, style=row_style),
                    Text(url, style=row_style),
                    Text(comment, style=row_style),
                    Text(status, style=result_style if result_style else row_style)
                )
            else:
                table.add_row(
                    protocol,
                    url,
                    comment,
                    Text(status, style=result_style) if result_style else status
                )

            # Update progress
            progress.update(task, advance=1)

    # Display results
    console.print(table)

    # Generate timestamp and prepare file paths
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = "test-results"
    # Ensure the results directory exists
    os.makedirs(results_dir, exist_ok=True)
    html_filename = f"{results_dir}/url_filtering_{timestamp}.html"
    csv_filename = f"{results_dir}/url_filtering_{timestamp}.csv"

    # Export results to CSV file
    console.print(f"[bold green]Exporting results to CSV file: {csv_filename}[/bold green]")
    with open(csv_filename, 'w', newline='') as csvfile:
        # Create CSV writer
        csv_writer = csv.writer(csvfile)

        # Write header row
        csv_writer.writerow(['Protocol', 'URL', 'Comment', 'Result'])

        # Write data rows
        for entry in urls_data:
            url = entry.get('URL', '')
            protocol = entry.get('Protocol', '')
            comment = entry.get('Comment', '')

            if not url or not protocol:
                continue

            # Test the URL again (or we could store results from the first run)
            try:
                status, detailed_result = test_url(url, protocol)
            except Exception as e:
                status = "Error"
                detailed_result = f"Error: {str(e)}"

            # Write to CSV
            csv_writer.writerow([protocol, url, comment, status])

    # Generate HTML report with tooltips

    console.print(f"[bold green]Exporting results to HTML file: {html_filename}[/bold green]")
    with open(html_filename, 'w') as htmlfile:
        # Write HTML header with tooltip styles
        htmlfile.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>URL Filtering Test Results</title>
    <style>
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .allowed {{ background-color: #e6ffe6; }} /* Light green */
        .blocked {{ background-color: #ffe6e6; }} /* Light red */
        .paused {{ background-color: #fffde6; }} /* Light yellow */
        .malicious {{ background-color: #ffe6e6 !important; }} /* Light red for malicious categories - override zebra-striping */

        /* Tooltip styling */
        [data-tooltip] {{
            position: relative;
            cursor: help;
        }}
        [data-tooltip] .tooltip-content {{
            display: none;
            position: absolute;
            left: 0;
            bottom: 100%;
            z-index: 100;
            background-color: #fffbe6; /* Light yellowish background */
            color: #333;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
            width: 400px;
            word-wrap: break-word;
            box-shadow: 0 0 5px rgba(0,0,0,0.3);
        }}
        /* Style for flipped tooltip (when displayed below instead of above) */
        [data-tooltip] .tooltip-content.flipped {{
            bottom: auto;
            top: 100%;
        }}
        [data-tooltip]:hover .tooltip-content {{
            display: block;
        }}
    </style>
    <script>
        // Function to ensure tooltips stay within page boundaries
        document.addEventListener('DOMContentLoaded', function() {{
            // Add mouseover event listener to all tooltip elements
            const tooltipElements = document.querySelectorAll('[data-tooltip]');
            tooltipElements.forEach(function(element) {{
                element.addEventListener('mouseenter', function() {{
                    const tooltip = this.querySelector('.tooltip-content');
                    if (!tooltip) return;

                    // Reset position to default first
                    tooltip.style.left = '0';
                    // Remove the flipped class by default
                    tooltip.classList.remove('flipped');

                    // Get tooltip dimensions and position
                    const tooltipRect = tooltip.getBoundingClientRect();
                    const viewportWidth = window.innerWidth;
                    const viewportHeight = window.innerHeight;

                    // Check if tooltip goes beyond right edge of viewport
                    if (tooltipRect.right > viewportWidth) {{
                        // Adjust position to keep it within viewport
                        tooltip.style.left = (viewportWidth - tooltipRect.right) + 'px';
                    }}

                    // Check if tooltip goes beyond top of viewport
                    if (tooltipRect.top < 0) {{
                        // Display below instead of above by adding the flipped class
                        tooltip.classList.add('flipped');
                    }} else {{
                        // Make sure the flipped class is removed if not needed
                        tooltip.classList.remove('flipped');
                    }}
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>URL Filtering Test Results</h1>
    <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <table>
        <tr>
            <th>Protocol</th>
            <th>URL</th>
            <th>Comment</th>
            <th>Result</th>
        </tr>
""")

        # Process each URL again for HTML output
        for entry in urls_data:
            url = entry.get('URL', '')
            protocol = entry.get('Protocol', '')
            comment = entry.get('Comment', '')

            if not url or not protocol:
                continue

            # Test the URL again (or we could store results from the first run)
            try:
                status, detailed_result = test_url(url, protocol)
            except Exception as e:
                status = "Error"
                detailed_result = f"Error: {str(e)}"

            # Determine row class based on "malicious" comment
            row_class = ' class="malicious"' if comment.lower() == "malicious" else ''

            # Determine result class based on status
            if status == "Allowed":
                result_class = ' class="allowed"'
            elif status == "Blocked":
                result_class = ' class="blocked"'
            elif status == "Paused":
                result_class = ' class="paused"'
            else:
                result_class = ''

            # Create tooltip HTML for detailed result
            tooltip_html = f'<span data-tooltip>{status}<div class="tooltip-content">{detailed_result}</div></span>'

            # Write table row
            htmlfile.write(f"""        <tr{row_class}>
            <td>{protocol}</td>
            <td>{url}</td>
            <td>{comment}</td>
            <td{result_class}>{tooltip_html}</td>
        </tr>
""")

        # Write HTML footer
        htmlfile.write("""    </table>
</body>
</html>""")

    console.print(f"[bold cyan]HTML file:[/bold cyan] {os.path.abspath(html_filename)}")
    input("\nPress Enter to return to the main menu...")


def test_url_filtering_for_all_groups(panos_device=None):
    """Test URL filtering for all user groups by making HTTP/HTTPS requests to a list of URLs.

    This function tests URL filtering policies across all user groups defined in the
    URL categories requirements file. It creates user-to-IP mappings for each group,
    tests all URLs for each group, and displays a comprehensive comparison of results.

    Args:
        panos_device: Optional PanOS device object. Required for creating user-to-IP mappings.

    Returns:
        None

    Note:
        This function:
        1. Reads the requirements for URL filtering using parse_url_categories()
        2. Gets all group names for managed URL categories
        3. Builds results in memory first
        4. For each group:
           - Creates an IP-to-user mapping using map_user_to_ip_and_group()
           - Tests all URLs
           - Stores the results for that group
        5. Displays the results in a table after all processing is complete

        Also includes special test cases for users with and without decryption.
    """
    from lib.category_parser import parse_url_categories

    console.print("[bold green]Testing URL filtering for all user groups...[/bold green]")

    if not panos_device:
        console.print("[bold red]Error:[/bold red] No PAN-OS device connection available.")
        input("\nPress Enter to return to the main menu...")
        return

    # Read URL filtering requirements
    console.print("Reading URL filtering requirements...")
    url_categories_requirements = parse_url_categories("../" + settings.URL_CATEGORIES_REQUIREMENTS_FILENAME)

    if not url_categories_requirements:
        console.print(f"[bold red]Error:[/bold red] Failed to read URL categories from {settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}")
        input("\nPress Enter to return to the main menu...")
        return

    # Get all group names for managed URL categories
    console.print("Getting all group names for managed URL categories...")
    groups = []
    for category in url_categories_requirements:
        if category.get("Action", "").lower() == settings.URL_ACTION_MANAGE.lower():
            user_id = category.get("UserID", "")
            if user_id and user_id not in groups:
                groups.append(user_id)

    if not groups:
        console.print("[bold red]Error:[/bold red] No managed URL categories with UserID found.")
        input("\nPress Enter to return to the main menu...")
        return

    console.print(f"Found {len(groups)} groups: {', '.join(groups)}")

    # Read URLs from file
    urls_data = parse_metadata_from_csv("URLs", "../" + settings.TEST_URLS_FILENAME, suppress_output=True)

    if not urls_data:
        console.print(f"[bold red]Error:[/bold red] No URLs found in {settings.TEST_URLS_FILENAME}")
        input("\nPress Enter to return to the main menu...")
        return

    # Use the global source IP for testing
    global SOURCE_IP_FOR_TESTING
    test_ip = SOURCE_IP_FOR_TESTING
    test_user = "test_user"

    # Dictionary to store results for each URL and group
    results = {}

    # Add two additional test cases
    special_cases = [
        {"name": "known-user (no decryption)", "group": None, "add_decryption": False},
        {"name": "known-user (with decryption)", "group": None, "add_decryption": True}
    ]

    # Calculate total tasks for progress bar (groups × URLs + special cases × URLs)
    total_tasks = (len(groups) + len(special_cases)) * len(urls_data)
    completed_tasks = 0

    # Set up progress bar for overall progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        # Create a task for the overall progress
        task = progress.add_task("[cyan]Testing URLs for all groups...", total=total_tasks)

        # Process special test cases first
        for special_case in special_cases:
            # Update progress description
            progress.update(task, description=f"[cyan]Testing {special_case['name']}...")

            # Create user-to-IP mapping for this special case
            # For special cases, we either add the user to no groups or only to the decryption group
            if special_case["group"] is None:
                # Use the map_user_to_ip_and_group function with skip_group_name=True
                # This will map the user to the IP and create empty entries for all groups
                # If add_decryption is True, it will also add the user to the decryption group
                map_user_to_ip_and_group(
                    panos_device, 
                    test_ip, 
                    None,  # group_name is not used when skip_group_name is True
                    test_user, 
                    groups, 
                    suppress_output=True, 
                    add_decryption_group=special_case["add_decryption"],
                    skip_group_name=True
                )

            # Process each URL
            for entry in urls_data:
                # Get URL and protocol
                url = entry.get('URL', '')
                protocol = entry.get('Protocol', '')

                if not url or not protocol:
                    # Update progress
                    completed_tasks += 1
                    progress.update(task, completed=completed_tasks)
                    continue

                # Create a unique key for this URL
                url_key = f"{protocol}:{url}"

                # Initialize results for this URL if not already done
                if url_key not in results:
                    results[url_key] = {
                        'protocol': protocol,
                        'url': url,
                        'comment': entry.get('Comment', ''),
                        'group_results': {}
                    }

                # Test the URL
                try:
                    status, detailed_result = test_url(url, protocol)
                except Exception as e:
                    status = "Error"
                    detailed_result = f"Error: {str(e)}"

                # Store both status and detailed result for this special case
                results[url_key]['group_results'][special_case['name']] = {
                    'status': status,
                    'detailed_result': detailed_result
                }

                # Update progress
                completed_tasks += 1
                progress.update(task, completed=completed_tasks)

        # Process each regular group
        for group in groups:
            # Update progress description
            progress.update(task, description=f"[cyan]Testing group {group}...")

            # Create user-to-IP mapping for this group
            map_user_to_ip_and_group(panos_device, test_ip, group, test_user, groups, suppress_output=True, add_decryption_group=True)

            # Process each URL
            for entry in urls_data:
                # Get URL and protocol
                url = entry.get('URL', '')
                protocol = entry.get('Protocol', '')

                if not url or not protocol:
                    # Update progress
                    completed_tasks += 1
                    progress.update(task, completed=completed_tasks)
                    continue

                # Create a unique key for this URL
                url_key = f"{protocol}:{url}"

                # Initialize results for this URL if not already done
                if url_key not in results:
                    results[url_key] = {
                        'protocol': protocol,
                        'url': url,
                        'comment': entry.get('Comment', ''),
                        'group_results': {}
                    }

                # Test the URL
                try:
                    status, detailed_result = test_url(url, protocol)
                except Exception as e:
                    status = "Error"
                    detailed_result = f"Error: {str(e)}"

                # Store both status and detailed result for this group
                results[url_key]['group_results'][group] = {
                    'status': status,
                    'detailed_result': detailed_result
                }

                # Update progress
                completed_tasks += 1
                progress.update(task, completed=completed_tasks)

    # Generate timestamp for filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = "test-results"
    # Ensure the results directory exists
    os.makedirs(results_dir, exist_ok=True)
    csv_filename = f"{results_dir}/url_filtering_all_groups_{timestamp}.csv"
    html_filename = f"{results_dir}/url_filtering_all_groups_{timestamp}.html"

    # Export results to CSV file
    console.print(f"[bold green]Exporting results to CSV file: {csv_filename}[/bold green]")
    with open(csv_filename, 'w', newline='') as csvfile:
        # Create CSV writer
        csv_writer = csv.writer(csvfile)

        # Write header row with special cases first, then regular groups
        special_case_names = [case['name'] for case in special_cases]
        header = ['Protocol', 'URL', 'Comment'] + special_case_names + groups
        csv_writer.writerow(header)

        # Write data rows
        for url_key, data in results.items():
            row = [data['protocol'], data['url'], data['comment']]

            # Add special case results first
            for special_case in special_cases:
                special_case_name = special_case['name']
                if special_case_name in data['group_results']:
                    row.append(data['group_results'][special_case_name]['status'])
                else:
                    row.append("Not tested")

            # Then add regular group results
            for group in groups:
                if group in data['group_results']:
                    row.append(data['group_results'][group]['status'])
                else:
                    row.append("Not tested")

            csv_writer.writerow(row)

    # Export results to HTML file
    console.print(f"[bold green]Exporting results to HTML file: {html_filename}[/bold green]")
    with open(html_filename, 'w') as htmlfile:
        # Write HTML header with tooltip styles
        htmlfile.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>URL Filtering Test Results for All Groups</title>
    <style>
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .allowed {{ background-color: #e6ffe6; }} /* Light green */
        .blocked {{ background-color: #ffe6e6; }} /* Light red */
        .paused {{ background-color: #fffde6; }} /* Light yellow */
        .malicious {{ background-color: #ffe6e6 !important; }} /* Light red for malicious categories - override zebra-striping */

        /* Tooltip styling */
        [data-tooltip] {{
            position: relative;
            cursor: help;
        }}
        [data-tooltip] .tooltip-content {{
            display: none;
            position: absolute;
            left: 0;
            bottom: 100%;
            z-index: 100;
            background-color: #fffbe6; /* Light yellowish background */
            color: #333;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
            width: 400px;
            word-wrap: break-word;
            box-shadow: 0 0 5px rgba(0,0,0,0.3);
        }}
        /* Style for flipped tooltip (when displayed below instead of above) */
        [data-tooltip] .tooltip-content.flipped {{
            bottom: auto;
            top: 100%;
        }}
        [data-tooltip]:hover .tooltip-content {{
            display: block;
        }}
    </style>
    <script>
        // Function to ensure tooltips stay within page boundaries
        document.addEventListener('DOMContentLoaded', function() {{
            // Add mouseover event listener to all tooltip elements
            const tooltipElements = document.querySelectorAll('[data-tooltip]');
            tooltipElements.forEach(function(element) {{
                element.addEventListener('mouseenter', function() {{
                    const tooltip = this.querySelector('.tooltip-content');
                    if (!tooltip) return;

                    // Reset position to default first
                    tooltip.style.left = '0';
                    // Remove the flipped class by default
                    tooltip.classList.remove('flipped');

                    // Get tooltip dimensions and position
                    const tooltipRect = tooltip.getBoundingClientRect();
                    const viewportWidth = window.innerWidth;
                    const viewportHeight = window.innerHeight;

                    // Check if tooltip goes beyond right edge of viewport
                    if (tooltipRect.right > viewportWidth) {{
                        // Adjust position to keep it within viewport
                        tooltip.style.left = (viewportWidth - tooltipRect.right) + 'px';
                    }}

                    // Check if tooltip goes beyond top of viewport
                    if (tooltipRect.top < 0) {{
                        // Display below instead of above by adding the flipped class
                        tooltip.classList.add('flipped');
                    }} else {{
                        // Make sure the flipped class is removed if not needed
                        tooltip.classList.remove('flipped');
                    }}
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>URL Filtering Test Results for All Groups</h1>
    <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <table>
        <tr>
            <th>Protocol</th>
            <th>URL</th>
            <th>Comment</th>
""")

        # Write special case headers first
        for special_case in special_cases:
            htmlfile.write(f"            <th>{special_case['name']}</th>\n")

        # Then write regular group headers
        for group in groups:
            htmlfile.write(f"            <th>{group}</th>\n")
        htmlfile.write("        </tr>\n")

        # Write data rows
        for url_key, data in results.items():
            # Determine row class based on "malicious" comment
            row_class = ' class="malicious"' if data['comment'].lower() == "malicious" else ''

            htmlfile.write(f"        <tr{row_class}>\n")
            htmlfile.write(f"            <td>{data['protocol']}</td>\n")
            htmlfile.write(f"            <td>{data['url']}</td>\n")
            htmlfile.write(f"            <td>{data['comment']}</td>\n")

            # Add special case results first
            for special_case in special_cases:
                special_case_name = special_case['name']
                if special_case_name in data['group_results']:
                    status = data['group_results'][special_case_name]['status']
                    detailed_result = data['group_results'][special_case_name]['detailed_result']

                    # Determine cell class based on status
                    if status == "Allowed":
                        cell_class = ' class="allowed"'
                    elif status == "Blocked":
                        cell_class = ' class="blocked"'
                    elif status == "Paused":
                        cell_class = ' class="paused"'
                    else:
                        cell_class = ''

                    # Create tooltip HTML for detailed result
                    tooltip_html = f'<span data-tooltip>{status}<div class="tooltip-content">{detailed_result}</div></span>'

                    htmlfile.write(f"            <td{cell_class}>{tooltip_html}</td>\n")
                else:
                    htmlfile.write(f"            <td>Not tested</td>\n")

            # Then add regular group results
            for group in groups:
                if group in data['group_results']:
                    status = data['group_results'][group]['status']
                    detailed_result = data['group_results'][group]['detailed_result']

                    # Determine cell class based on status
                    if status == "Allowed":
                        cell_class = ' class="allowed"'
                    elif status == "Blocked":
                        cell_class = ' class="blocked"'
                    elif status == "Paused":
                        cell_class = ' class="paused"'
                    else:
                        cell_class = ''

                    # Create tooltip HTML for detailed result
                    tooltip_html = f'<span data-tooltip>{status}<div class="tooltip-content">{detailed_result}</div></span>'

                    htmlfile.write(f"            <td{cell_class}>{tooltip_html}</td>\n")
                else:
                    htmlfile.write(f"            <td>Not tested</td>\n")

            htmlfile.write("        </tr>\n")

        # Write HTML footer
        htmlfile.write("""    </table>
</body>
</html>""")

    console.print(f"[bold green]Results exported to:[/bold green]")
    console.print(f"[bold cyan]CSV file:[/bold cyan] {os.path.abspath(csv_filename)}")
    console.print(f"[bold cyan]HTML file:[/bold cyan] {os.path.abspath(html_filename)}")
    input("\nPress Enter to return to the main menu...")


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
BLOCKED_IP_SENTINEL = "Not resolved"          # displayed IP when the firewall RSTs
CSV_DIR            = "test-results"           # output folder

# ──────────────────────────────────────────────────────────────────────────────
# Helper – normalise “connection reset” exceptions
# ──────────────────────────────────────────────────────────────────────────────
def _blocked(exc: Exception) -> str:
    """Return a sentinel value when a connection-reset or firewall-block is detected.

    This helper function normalizes various connection reset exceptions and returns
    a consistent sentinel value (BLOCKED_IP_SENTINEL) when a firewall block is detected.

    Args:
        exc: The exception that was raised during a connection attempt

    Returns:
        str: BLOCKED_IP_SENTINEL if the exception indicates a connection reset or
             firewall block, otherwise "Error: {exc}"
    """
    if isinstance(exc, ConnectionResetError):
        return BLOCKED_IP_SENTINEL
    txt = str(exc)
    if ("10054" in txt) or ("forcibly closed" in txt) or ("Connection reset" in txt):
        return BLOCKED_IP_SENTINEL
    return f"Error: {exc}"

# ──────────────────────────────────────────────────────────────────────────────
# DNS resolver functions
# ──────────────────────────────────────────────────────────────────────────────
def resolve_dns_over_tls(fqdn: str, dns_server: str, timeout: float = 5.0) -> str:
    """Resolve a domain name using DNS-over-TLS (RFC 7858).

    This function performs a DNS lookup over an encrypted TLS connection to the
    specified DNS server. It returns the first A record found, or an appropriate
    error message if the lookup fails or is blocked.

    Args:
        fqdn: The fully qualified domain name to resolve
        dns_server: The DNS server to use for the lookup
        timeout: Maximum time in seconds to wait for a response (default: 5.0)

    Returns:
        str: One of the following:
            - The first A record IP address if found
            - "No A records found" if the lookup succeeded but no A records exist
            - "Not resolved" if the connection was reset (likely firewall block)
            - "Error: ..." with details if another error occurred
    """
    try:
        query = dns.message.make_query(fqdn, dns.rdatatype.A)
        ctx   = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp  = dns.query.tls(query, where=dns_server, port=853,
                              timeout=timeout, ssl_context=ctx)

        ips = [
            rdata.address
            for rrset in resp.answer
            if rrset.rdtype == dns.rdatatype.A
            for rdata in rrset
        ]
        return ips[0] if ips else "No A records found"
    except Exception as exc:                   # pragma: no cover
        return _blocked(exc)


def resolve_dns_over_https(fqdn: str, timeout: float = 5.0) -> str:
    """Resolve a domain name using DNS-over-HTTPS (RFC 8484).

    This function performs a DNS lookup over HTTPS to the DNS server specified in
    settings.DNS_OVER_HTTPS_URL. It supports both RFC 8484 wire-format endpoints
    and JSON-style endpoints. It returns the first A record found, or an appropriate
    error message if the lookup fails or is blocked.

    Args:
        fqdn: The fully qualified domain name to resolve
        timeout: Maximum time in seconds to wait for a response (default: 5.0)

    Returns:
        str: One of the following:
            - The first A record IP address if found
            - "No A records found" if the lookup succeeded but no A records exist
            - "Not resolved" if the connection was reset (likely firewall block)
            - "Error: ..." with details if another error occurred
    """
    doh_url = settings.DNS_OVER_HTTPS_URL.rstrip("/")
    try:
        # ── RFC 8484 wire-format endpoints ( …/dns-query ) ────────────────────
        if doh_url.endswith("dns-query"):
            query   = dns.message.make_query(fqdn, dns.rdatatype.A)
            encoded = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode()
            r = requests.get(
                doh_url,
                params={"dns": encoded},
                headers={"Accept": "application/dns-message"},
                timeout=timeout,
                verify=False  # Accept self-signed certificates
            )
            if r.status_code != 200:
                return f"Error: HTTP {r.status_code}"
            answer = dns.message.from_wire(r.content)
            ips = [
                rdata.address
                for rrset in answer.answer
                if rrset.rdtype == dns.rdatatype.A
                for rdata in rrset
            ]
            return ips[0] if ips else "No A records found"

        # ── JSON variant ( …/resolve , …/dns-json ) ──────────────────────────
        r = requests.get(
            doh_url,
            params={"name": fqdn, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
            verify=False  # Accept self-signed certificates
        )
        if r.status_code != 200:
            return f"Error: HTTP {r.status_code}"
        for ans in r.json().get("Answer", []):
            if ans.get("type") == 1:           # A-record
                return ans.get("data", "")
        return "No A records found"

    except requests.exceptions.ConnectionError as exc:
        return _blocked(exc)
    except Exception as exc:                   # pragma: no cover
        return _blocked(exc)


def resolve_plain_dns(fqdn: str, dns_server: str, timeout: float = 5.0) -> str:
    """Resolve a domain name using plain DNS over UDP/TCP port 53.

    This function performs a standard DNS lookup using the specified DNS server.
    It returns the first A record found, or an appropriate error message if the
    lookup fails or is blocked.

    Args:
        fqdn: The fully qualified domain name to resolve
        dns_server: The DNS server to use for the lookup
        timeout: Maximum time in seconds to wait for a response (default: 5.0)

    Returns:
        str: One of the following:
            - The first A record IP address if found
            - "No A records found" if the lookup succeeded but no A records exist
            - "Not resolved" if the connection was reset (likely firewall block)
            - "Error: ..." with details if another error occurred
    """
    try:
        res              = dns.resolver.Resolver()
        res.nameservers  = [dns_server]
        res.lifetime     = timeout
        answers          = res.resolve(fqdn, "A")
        return str(answers[0]) if answers else "No A records found"
    except Exception as exc:                   # pragma: no cover
        return _blocked(exc)

# ──────────────────────────────────────────────────────────────────────────────
# Classification helpers
# ──────────────────────────────────────────────────────────────────────────────
def _classify(ip: str) -> tuple[str, str]:
    """Map IP/result-string to action and rich-formatted action.

    This function classifies a DNS resolution result into one of four categories:
    Sinkholed, Allowed, Blocked, or Unknown. It returns both the plain action string
    and a rich-formatted version for display.

    Args:
        ip: The IP address or error string returned from a DNS resolution function

    Returns:
        tuple[str, str]: A tuple containing:
            - action: One of "Sinkholed", "Allowed", "Blocked", or "Unknown"
            - rich_action: The same action with rich text formatting for display
    """
    if ip == BLOCKED_IP_SENTINEL:
        return "Blocked", "[bold yellow]Blocked[/bold yellow]"
    if not ip or ip.startswith("Error:") or ip == "No A records found":
        return "Unknown", "Unknown"
    if ip == settings.DNS_SINKHOLE_RESOLVED_ADDRESS:
        return "Sinkholed", "[bold red]Sinkholed[/bold red]"
    return "Allowed", "[bold green]Allowed[/bold green]"


def _cls_css(action: str) -> str:
    """Return the CSS class name for HTML export based on action.

    This function maps action strings to CSS class names for HTML report styling.

    Args:
        action: The action string, one of "Sinkholed", "Allowed", "Blocked", etc.

    Returns:
        str: The CSS class name to use for this action in HTML reports
    """
    return {
        "Sinkholed": "sinkholed",
        "Allowed":   "allowed",
        "Blocked":   "error",
    }.get(action, "error")

# ──────────────────────────────────────────────────────────────────────────────
# Main routine
# ──────────────────────────────────────────────────────────────────────────────
def test_dns_security(panos_device=None) -> None:  # noqa: D401
    """Test DNS security by resolving domains using different DNS resolution methods.

    This function tests DNS security by resolving domain names using three different
    DNS resolution methods (DNS-over-TLS, DNS-over-HTTPS, and plain DNS) and comparing
    the results. It displays the results in a table and exports them to CSV and HTML files.

    Args:
        panos_device: Optional PanOS device object. Not directly used in this function
                      but included for consistency with other test functions.

    Returns:
        None
    """
    console.print("[bold green]Testing DNS Security…[/bold green]")

    dns_server = (
        input(f"Enter DNS server address [`{settings.DEFAULT_DNS_SERVER}`]: ")
        or settings.DEFAULT_DNS_SERVER
    )

    fqdns_data = parse_metadata_from_csv(
        "FQDNs",
        os.path.join("..", settings.TEST_FQDNS_FILENAME),
        suppress_output=True,
    )
    if not fqdns_data:
        console.print(f"[bold red]Error:[/bold red] No FQDNs found in {settings.TEST_FQDNS_FILENAME}")
        input("\nPress Enter to return to the main menu…")
        return

    # ── Build Rich table skeleton ────────────────────────────────────────────
    table = Table(title=f"DNS Resolution Results (using {dns_server})")
    for col, style in [
        ("Description", "magenta"), ("FQDN", "cyan"),
        ("DNS-TLS", "green"), ("DoT Action", None),
        ("DNS-HTTPS", "green"), ("DoH Action", None),
        ("Plain DNS", "green"), ("Plain Action", None),
        ("DNS Sec Policy", "yellow"),
    ]:
        table.add_column(col, style or "")

    results: List[Dict[str, str]] = []

    # ── Resolve each FQDN ────────────────────────────────────────────────────
    for entry in fqdns_data:
        fqdn = entry.get("FQDN") or entry.get("fqdn")
        if not fqdn:
            continue
        desc = entry.get("Description", "n/a")
        pol  = entry.get("DNS Security Policy", "n/a")

        dot_ip   = resolve_dns_over_tls(fqdn, dns_server)
        doh_ip   = resolve_dns_over_https(fqdn)
        plain_ip = resolve_plain_dns(fqdn, dns_server)

        dot_act,   dot_rich   = _classify(dot_ip)
        doh_act,   doh_rich   = _classify(doh_ip)
        plain_act, plain_rich = _classify(plain_ip)

        table.add_row(
            desc, fqdn,
            dot_ip,   dot_rich,
            doh_ip,   doh_rich,
            plain_ip, plain_rich,
            pol,
        )

        results.append(
            dict(
                description=desc, fqdn=fqdn,
                dot_ip=dot_ip,     dot_action=dot_act,
                doh_ip=doh_ip,     doh_action=doh_act,
                plain_ip=plain_ip, plain_action=plain_act,
                dns_security_policy=pol,
            )
        )

    console.print(table)

    # ──────────────────────────── Export section ─────────────────────────────
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(CSV_DIR, exist_ok=True)
    csv_path  = os.path.join(CSV_DIR, f"dns_security_{timestamp}.csv")
    html_path = os.path.join(CSV_DIR, f"dns_security_{timestamp}.html")

    # ----- CSV (force UTF-8 to dodge cp1252 on Windows) ----------------------
    console.print(f"[bold green]Exporting results to CSV:[/bold green] {csv_path}")
    with open(csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow([
            "Description", "FQDN",
            "DNS over TLS IP", "DNS over TLS Action",
            "DNS over HTTPS IP", "DNS over HTTPS Action",
            "Plain DNS IP", "Plain DNS Action",
            "DNS Security Policy",
        ])
        for row in results:
            writer.writerow([
                row["description"], row["fqdn"],
                row["dot_ip"],   row["dot_action"],
                row["doh_ip"],   row["doh_action"],
                row["plain_ip"], row["plain_action"],
                row["dns_security_policy"],
            ])

    # ----- HTML --------------------------------------------------------------
    console.print(f"[bold green]Exporting results to HTML:[/bold green] {html_path}")
    with open(html_path, "w", encoding="utf-8") as fp:
        fp.write(f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DNS Security Test Results</title>
<style>
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#f2f2f2}}
tr:nth-child(even){{background:#f9f9f9}}
.allowed{{background:#e6ffe6}}
.sinkholed{{background:#ffe6e6}}
.error{{background:#fff6e6}}
</style>
</head>
<body>
<h1>DNS Security Test Results</h1>
<p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>DNS Server: {dns_server}</p>
<table>
<tr>
  <th>Description</th><th>FQDN</th>
  <th>DNS-TLS IP</th><th>DNS-TLS Action</th>
  <th>DNS-HTTPS IP</th><th>DNS-HTTPS Action</th>
  <th>Plain DNS IP</th><th>Plain DNS Action</th>
  <th>DNS Security Policy</th>
</tr>
""")

        for row in results:
            tr_class = _cls_css(row["plain_action"])
            fp.write(f'  <tr class="{tr_class}">\n')
            for which in ("description", "fqdn",
                          "dot_ip",   "dot_action",
                          "doh_ip",   "doh_action",
                          "plain_ip", "plain_action",
                          "dns_security_policy"):
                css = _cls_css(row[f"{which.split('_')[0]}_action"]) \
                      if which.endswith("action") or which.endswith("ip") else ""
                fp.write(f'    <td class="{css}">{row[which]}</td>\n')
            fp.write("  </tr>\n")

        fp.write("</table>\n</body>\n</html>")

    # ----- Done --------------------------------------------------------------
    console.print(f"[bold cyan]CSV:[/bold cyan]  {os.path.abspath(csv_path)}")
    console.print(f"[bold cyan]HTML:[/bold cyan] {os.path.abspath(html_path)}")
    input("\nPress Enter to return to the main menu…")


def set_source_ip_for_testing():
    """Set the source IP address for testing.

    This function prompts the user for an IP address to use for testing, validates
    the format, and updates the global SOURCE_IP_FOR_TESTING variable.

    Args:
        None

    Returns:
        None

    Note:
        This function:
        1. Prompts the user for an IP address
        2. Validates the IP address format
        3. Updates the global SOURCE_IP_FOR_TESTING variable
    """
    global SOURCE_IP_FOR_TESTING

    console.print("[bold green]Setting source IP for testing...[/bold green]")
    console.print(f"Current source IP: [cyan]{SOURCE_IP_FOR_TESTING}[/cyan]")

    # Prompt for IP address with validation
    while True:
        ip_address = input('Enter new source IP address: ')

        # Validate IPv4 address format
        ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        ipv4_match = re.match(ipv4_pattern, ip_address)

        if ipv4_match:
            # Validate each octet is between 0-255
            valid_ip = True
            for octet in ipv4_match.groups():
                if int(octet) > 255:
                    valid_ip = False
                    break

            if valid_ip:
                SOURCE_IP_FOR_TESTING = ip_address
                console.print(f"[bold green]Source IP for testing set to: [cyan]{SOURCE_IP_FOR_TESTING}[/cyan][/bold green]")
                break
            else:
                console.print("[bold red]Error:[/bold red] Invalid IPv4 address. Each octet must be between 0-255.")
        else:
            console.print("[bold red]Error:[/bold red] Invalid address format. Please enter a valid IPv4 address.")

    input("\nPress Enter to return to the main menu...")


def set_domain_prefix():
    """Set the domain prefix for user and group names.

    This function allows the user to set or clear a domain prefix that will be added
    to all user and group names in the format <domain>\<user|group name>.

    Args:
        None

    Returns:
        None

    Note:
        This function:
        1. Prompts the user if they want to add a domain prefix to all group names and usernames
        2. If yes, suggests the value of settings.AD_DOMAIN_NAME as a default value
        3. If no, sets the domain prefix to an empty string
        4. Updates the global DOMAIN_PREFIX variable
    """
    global DOMAIN_PREFIX

    console.print("[bold green]Setting domain prefix for user and group names...[/bold green]")
    console.print(f"Current domain prefix: [cyan]{DOMAIN_PREFIX if DOMAIN_PREFIX else 'None'}[/cyan]")

    # Ask if a domain prefix should be added
    while True:
        add_prefix = input('Add a domain prefix to all group names and user names? (y/n): ').lower()
        if add_prefix in ['y', 'yes']:
            # Suggest the value of settings.AD_DOMAIN_NAME as a default value
            default_domain = settings.AD_DOMAIN_NAME
            domain_prefix = input(f'Enter domain prefix [`{default_domain}`]: ') or default_domain
            DOMAIN_PREFIX = domain_prefix
            console.print(f"[bold green]Domain prefix set to: [cyan]{DOMAIN_PREFIX}[/cyan][/bold green]")
            break
        elif add_prefix in ['n', 'no']:
            DOMAIN_PREFIX = ""
            console.print("[bold green]Domain prefix cleared[/bold green]")
            break
        else:
            console.print("[bold red]Error:[/bold red] Please enter 'y' or 'n'.")

    input("\nPress Enter to return to the main menu...")


def set_decryption_group():
    """Set the user group for decryption.

    This function allows the user to set or clear the user group that will be used
    for decryption testing. Users added to this group will have their traffic decrypted.

    Args:
        None

    Returns:
        None

    Note:
        This function:
        1. Prompts the user if they would like to set a group for decryption
        2. If yes, suggests "ug-decryption" as a default value
        3. Updates the global DECRYPTION_GROUP variable
    """
    global DECRYPTION_GROUP

    console.print("[bold green]Setting user group for decryption...[/bold green]")
    console.print(f"Current decryption group: [cyan]{DECRYPTION_GROUP if DECRYPTION_GROUP else 'None'}[/cyan]")

    # Ask if a decryption group should be set
    while True:
        set_group = input('Would you like to set a group for decryption? (y/n): ').lower()
        if set_group in ['y', 'yes']:
            # Suggest "ug-decryption" as a default value
            default_group = "ug-decryption"
            decryption_group = input(f'Enter decryption group name [`{default_group}`]: ') or default_group
            DECRYPTION_GROUP = decryption_group
            console.print(f"[bold green]Decryption group set to: [cyan]{DECRYPTION_GROUP}[/cyan][/bold green]")
            break
        elif set_group in ['n', 'no']:
            DECRYPTION_GROUP = ""
            console.print("[bold green]Decryption group cleared[/bold green]")
            break
        else:
            console.print("[bold red]Error:[/bold red] Please enter 'y' or 'n'.")

    input("\nPress Enter to return to the main menu...")


def display_banner():
    """Display a banner explaining what the script does.

    This function creates and displays a formatted panel with information about
    the script's functionality, including user/group mapping, URL filtering,
    and DNS security testing capabilities.

    Args:
        None

    Returns:
        None
    """
    banner_content = "This script helps you test the firewall security policy\n\n"
    banner_content += "It provides functionality to:\n"
    banner_content += "• Create user and group mappings\n"
    banner_content += "• Test URL filtering capabilities\n"
    banner_content += "• Test URL filtering for all user groups\n"
    banner_content += "• Test DNS Security features\n\n"
    banner_content += "Once connected to a firewall, you will be presented with a menu to select a test."

    panel = Panel.fit(banner_content, title="PAN-OS Policy Test Tool", border_style="green")
    console.print(panel)


def display_menu():
    """Display the interactive menu with eight options.

    This function displays a formatted panel with the current settings and menu options.
    It prompts the user to select an option and validates the input to ensure it's
    a number between 1 and 8.

    Args:
        None

    Returns:
        int: The user's choice as an integer (1-8)
    """
    global SOURCE_IP_FOR_TESTING, DOMAIN_PREFIX, DECRYPTION_GROUP
    menu_content = f"Current source IP for testing: [cyan]{SOURCE_IP_FOR_TESTING}[/cyan]\n"
    menu_content += f"Current domain prefix: [cyan]{DOMAIN_PREFIX if DOMAIN_PREFIX else 'None'}[/cyan]\n"
    menu_content += f"Current decryption group: [cyan]{DECRYPTION_GROUP if DECRYPTION_GROUP else 'None'}[/cyan]\n\n"
    menu_content += "Please select an option:\n\n"
    menu_content += "1. Set source IP for testing\n"
    menu_content += "2. Set domain prefix for user and group names\n"
    menu_content += "3. Set user group for decryption\n"
    menu_content += "4. Create a user and group mapping\n"
    menu_content += "5. Test URL filtering for current user/group mapping\n"
    menu_content += "6. Test URL filtering for all user groups \n"
    menu_content += "7. Test DNS Security\n"
    menu_content += "8. Exit\n"

    panel = Panel.fit(menu_content, title="Policy Test Menu", border_style="blue")
    console.print(panel)

    while True:
        try:
            choice = input("\nEnter your choice (1-8): ").strip()
            choice = int(choice)
            if 1 <= choice <= 8:
                return choice
            else:
                console.print("[bold red]Please enter a number between 1 and 8.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid input. Please enter a number.[/bold red]")


def main():
    """Main function to run the interactive menu.

    This function serves as the entry point for the policy testing tool. It displays
    a banner explaining the script's functionality, initializes the firewall connection,
    and then enters a loop to display the menu and process user selections.

    Args:
        None

    Returns:
        None

    Note:
        The firewall connection is initialized once before displaying the menu, and
        the panos_device object is passed to all functions called from the menu.
    """
    # Display banner explaining what the script does
    display_banner()

    # Initialize the firewall once before displaying the menu
    console.print("[bold green]Initializing firewall connection...[/bold green]")
    panos_device = initialize_firewall()

    while True:
        choice = display_menu()

        if choice == 1:
            set_source_ip_for_testing()
        elif choice == 2:
            set_domain_prefix()
        elif choice == 3:
            set_decryption_group()
        elif choice == 4:
            create_user_group_mapping(panos_device)
        elif choice == 5:
            test_url_filtering(panos_device)
        elif choice == 6:
            test_url_filtering_for_all_groups(panos_device)
        elif choice == 7:
            test_dns_security(panos_device)
        elif choice == 8:
            console.print("[bold green]Exiting the program. Goodbye![/bold green]")
            break


if __name__ == "__main__":
    main()
