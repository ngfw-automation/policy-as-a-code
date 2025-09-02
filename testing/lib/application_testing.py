"""
Application-layer test stubs.

This module implements application testing functionality by prompting the user for
destination IP, protocol, port, and application name, and then calling the
test_security_policy_match() method with these values.

Example usage:
    panos_device.test_security_policy_match(source="<source IP>", destination="<a static public IP address, say for example.com>", port=<port>, protocol=<IP protocol>,
                                  application="<application-name>", from_zone=settings.ZONE_INSIDE, to_zone=settings.ZONE_OUTSIDE, show_all=False)
"""
import re
import sys
import os
import csv
import datetime
from pathlib import Path
import unicodedata

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from lib.rich_output import console
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import settings
from testing.lib.dns_testing import _resolve_plain_text_dns
import testing.lib.user_identity as uid
from testing.lib.auxiliary import NORMALIZED_BUILT_IN_APPS

# Maximum number of applications to test (0 means test all)
MAX_APPS_TO_TEST = 100

def _sanitize_text(text):
    """
    Sanitize text to ensure it can be safely written to CSV.

    Args:
        text (str): The text to sanitize

    Returns:
        str: Sanitized text
    """
    if not text:
        return "N/A"

    # Convert to string if not already
    if not isinstance(text, str):
        text = str(text)

    # Replace problematic characters
    try:
        # Normalize Unicode characters
        text = unicodedata.normalize('NFKD', text)

        # Replace control characters and other problematic characters
        text = ''.join(ch if unicodedata.category(ch)[0] != 'C' else ' ' for ch in text)

        # More aggressive cleanup for problematic characters
        # Remove specific problematic characters
        text = text.replace('\x9d', '')
        text = text.replace('\ufffd', '')

        # Replace any non-ASCII characters with their ASCII approximation or remove them
        result = ""
        for char in text:
            if ord(char) < 128:  # ASCII characters only
                result += char
            else:
                # Skip non-ASCII characters
                pass

        return result
    except Exception as e:
        # If any error occurs during sanitization, return a safe value
        return "Text contains unsupported characters"

def test_application(panos_device=None):
    """
    Test application functionality by prompting for inputs and calling test_security_policy_match().

    Args:
        panos_device: The PAN-OS device object to use for testing.
    """
    if not panos_device:
        console.print("[bold red]No firewall object. Please connect to a firewall first.[/bold red]")
        return

    if not uid.SOURCE_IP_FOR_TESTING:
        console.print("[bold red]Source IP not set. Please set the source IP first (option 1 in the main menu).[/bold red]")
        return

    # Resolve example.com to get default destination IP
    default_dns_server = settings.DEFAULT_DNS_SERVER
    try:
        ip_addresses = _resolve_plain_text_dns("example.com", default_dns_server)
        if ip_addresses == "No A records found" or ip_addresses.startswith("Error"):
            default_dest_ip = "93.184.216.34"  # Fallback IP for example.com
        else:
            # Only use the first IP address returned
            default_dest_ip = ip_addresses.split(";")[0].strip()
    except Exception:
        default_dest_ip = "93.184.216.34"  # Fallback IP for example.com

    # Prompt for application name and verify it exists
    while True:
        application = input("Application name: ")
        if not application:
            console.print("[bold red]Application name cannot be empty.[/bold red]")
            continue

        # Check if the application exists in the built-in apps
        if application in NORMALIZED_BUILT_IN_APPS:
            app_info = NORMALIZED_BUILT_IN_APPS[application]

            # Get application details
            description = app_info.get('description', 'N/A')
            risk = app_info.get('risk', 'N/A')
            risk_style = "green" if risk in ["1", "2"] else "yellow" if risk in ["3", "4"] else "red"

            # Format default ports
            default_ports = app_info.get('default-ports')
            ports_str = "N/A"
            if default_ports:
                if isinstance(default_ports, list):
                    ports_str = ", ".join(default_ports)
                else:
                    ports_str = str(default_ports)

            # Extract first default port and protocol
            default_port = _extract_port_number(default_ports)
            default_protocol = "tcp"  # Default to TCP

            # If default_ports contains protocol information, extract it
            if default_ports and isinstance(default_ports, (str, list)):
                ports_info = default_ports[0] if isinstance(default_ports, list) else default_ports
                if "udp/" in ports_info.lower():
                    default_protocol = "udp"

            # Create content for the banner with all application details
            label_width = 25
            content = f"{'App name:'.ljust(label_width)} [bold cyan]{application}[/bold cyan]\n"
            content += f"{'App description:'.ljust(label_width)} [blue]{description}[/blue]\n"
            content += f"{'Default port number(s):'.ljust(label_width)} [magenta]{ports_str}[/magenta]\n"
            content += f"{'App risk level:'.ljust(label_width)} [{risk_style}]{risk}[/{risk_style}]"

            # Print the banner with application details
            console.print(Panel.fit(
                content,
                title="APPLICATION DETAILS",
                border_style="cyan"
            ))

            break
        else:
            # Suggest similar applications
            similar_apps = []
            for app_name in NORMALIZED_BUILT_IN_APPS.keys():
                if application.lower() in app_name.lower():
                    similar_apps.append(app_name)

            if similar_apps:
                console.print(f"[bold yellow]Application '{application}' not found. Did you mean one of these?[/bold yellow]")
                for i, app in enumerate(similar_apps[:5]):  # Show up to 5 suggestions
                    console.print(f"  {i+1}. {app}")
                console.print("[bold yellow]Please enter the exact application name.[/bold yellow]")
            else:
                console.print(f"[bold red]Application '{application}' not found. Please enter a valid application name.[/bold red]")
            continue

    # Prompt for destination IP
    while True:
        dest_ip = input(f"Destination IP address [`{default_dest_ip}`]: ") or default_dest_ip
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", dest_ip):
            break
        console.print("[bold red]Invalid IP address format. Please enter a valid IP address.[/bold red]")

    # Prompt for protocol (tcp or udp)
    while True:
        protocol_str = input(f"IP protocol (tcp/udp) [`{default_protocol}`]: ") or default_protocol
        protocol_str = protocol_str.lower()
        if protocol_str == "tcp":
            protocol = 6
            break
        elif protocol_str == "udp":
            protocol = 17
            break
        console.print("[bold red]Invalid protocol. Please enter 'tcp' or 'udp'.[/bold red]")

    # Prompt for port number
    while True:
        port_str = input(f"Port number (1-65535) [`{default_port}`]: ") or str(default_port)
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            console.print("[bold red]Port number must be between 1 and 65535.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid port number. Please enter a number between 1 and 65535.[/bold red]")

    # Call test_security_policy_match with the provided values
    console.print("[bold green]Testing security policy match...[/bold green]")
    try:
        result = panos_device.test_security_policy_match(
            source=uid.SOURCE_IP_FOR_TESTING,
            destination=dest_ip,
            port=port,
            protocol=protocol,
            application=application,
            from_zone=settings.ZONE_INSIDE,
            to_zone=settings.ZONE_OUTSIDE,
            show_all=False
        )

        # Output the results
        console.print("[bold green]Test results:[/bold green]")

        # Get application details
        app_info = NORMALIZED_BUILT_IN_APPS.get(application, {})
        description = app_info.get('description', 'N/A')
        risk = app_info.get('risk', 'N/A')
        risk_style = "green" if risk in ["1", "2"] else "yellow" if risk in ["3", "4"] else "red"

        # Format default ports
        default_ports = app_info.get('default-ports')
        ports_str = "N/A"
        if default_ports:
            if isinstance(default_ports, list):
                ports_str = ", ".join(default_ports)
            else:
                ports_str = str(default_ports)

        # Process and display each result in a Rich banner
        for rule in result:
            action = rule.get('action', 'unknown')
            name = rule.get('name', 'unknown')
            index = rule.get('index', 'unknown')

            # Set border color based on action
            border_style = "green" if action.lower() == "allow" else "red"
            header = "ALLOWED" if action.lower() == "allow" else "DENIED"

            # Create content for the banner with all application details
            # Define a consistent label width for alignment
            label_width = 25

            content = f"{'App name:'.ljust(label_width)} [bold cyan]{application}[/bold cyan]\n"
            content += f"{'Rule name:'.ljust(label_width)} [cyan]{name}[/cyan]\n"
            content += f"{'Rule index:'.ljust(label_width)} [yellow]{index}[/yellow]\n"
            content += f"{'App description:'.ljust(label_width)} [blue]{description}[/blue]\n"
            content += f"{'Default port number(s):'.ljust(label_width)} [magenta]{ports_str}[/magenta]\n"
            content += f"{'App risk level:'.ljust(label_width)} [{risk_style}]{risk}[/{risk_style}]"

            # Print the banner with action as title
            console.print(Panel.fit(
                content,
                title=header,
                border_style=border_style
            ))

        # Wait for Enter before returning to the menu
        input("\nPress Enter to return to the menu...")
    except Exception as e:
        console.print(f"[bold red]Error testing security policy match: {e}[/bold red]")
        # Wait for Enter before returning to the menu
        input("\nPress Enter to return to the menu...")

def _extract_port_number(default_ports):
    """
    Extract the first valid port number from the default ports string.

    Args:
        default_ports: String or list containing default port information

    Returns:
        int: The first valid port number found, or 443 if only dynamic ports are available
    """
    # If default_ports is None, return 443 as fallback
    if not default_ports:
        return 443

    # Convert to string if it's a list
    if isinstance(default_ports, list):
        if not default_ports:  # Empty list
            return 443
        ports_str = default_ports[0]
    else:
        ports_str = str(default_ports)

    # Parse the port string to extract the first valid port number
    # Examples: "tcp/3004,3002", "tcp/80,443", "tcp/dynamic", "tcp/80,8000,20000,20200,dynamic, udp/dynamic"

    # First, check if there's a protocol prefix (tcp/ or udp/)
    if '/' in ports_str:
        # Split by '/' and take the second part (the actual ports)
        parts = ports_str.split('/')
        if len(parts) > 1:
            ports_str = parts[1]

    # Split by comma to get individual port values
    port_values = [p.strip() for p in ports_str.split(',')]

    # Look for the first numeric port
    for port_value in port_values:
        if port_value.isdigit():
            return int(port_value)

    # If we only have "dynamic" ports, return 443 as fallback
    return 443

def test_all_applications(panos_device=None):
    """
    Test all applications using their default ports and output results to a CSV file.

    This function loops through all applications in NORMALIZED_BUILT_IN_APPS,
    tests each one using the first default port found, and writes the results to a CSV file.
    A Rich progress bar is displayed to show the testing status.

    Args:
        panos_device: The PAN-OS device object to use for testing.
    """
    if not panos_device:
        console.print("[bold red]No firewall object. Please connect to a firewall first.[/bold red]")
        return

    if not uid.SOURCE_IP_FOR_TESTING:
        console.print("[bold red]Source IP not set. Please set the source IP first (option 1 in the main menu).[/bold red]")
        return

    # Resolve example.com to get default destination IP
    default_dns_server = settings.DEFAULT_DNS_SERVER
    try:
        ip_addresses = _resolve_plain_text_dns("example.com", default_dns_server)
        if ip_addresses == "No A records found" or ip_addresses.startswith("Error"):
            default_dest_ip = "93.184.216.34"  # Fallback IP for example.com
        else:
            # Only use the first IP address returned
            default_dest_ip = ip_addresses.split(";")[0].strip()
    except Exception:
        default_dest_ip = "93.184.216.34"  # Fallback IP for example.com

    # Create a timestamp for the CSV filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"app_id_test_results_{timestamp}.csv"

    # Ensure the test-results directory exists
    results_dir = Path("test-results")
    results_dir.mkdir(exist_ok=True)

    csv_path = results_dir / csv_filename

    # Determine how many applications to test
    all_apps = list(NORMALIZED_BUILT_IN_APPS.items())

    # Prompt user for number of apps to test
    num_apps_input = input(f"Number of applications to test [default: {MAX_APPS_TO_TEST}, 0 for all]: ") or str(MAX_APPS_TO_TEST)
    try:
        num_apps = int(num_apps_input)
        if num_apps < 0:
            console.print("[bold red]Number of apps must be non-negative. Using default.[/bold red]")
            num_apps = MAX_APPS_TO_TEST
    except ValueError:
        console.print("[bold red]Invalid input. Using default.[/bold red]")
        num_apps = MAX_APPS_TO_TEST

    if num_apps > 0:
        apps_to_test = all_apps[:num_apps]
        total_apps = len(apps_to_test)
        console.print(f"[bold green]Starting App-ID test for the first {total_apps} applications...[/bold green]")
    else:
        apps_to_test = all_apps
        total_apps = len(apps_to_test)
        console.print(f"[bold green]Starting App-ID test for all {total_apps} applications...[/bold green]")

    console.print(f"[bold]Results will be saved to:[/bold] {csv_path}")

    # Create CSV file and write header
    with open(csv_path, 'w', newline='', encoding='latin-1') as csvfile:
        fieldnames = ['Application', 'Category', 'Subcategory', 'Risk', 'Default Ports', 'Chosen Port', 
                      'Chosen Protocol', 'Username', 'Group Name',
                      'Rule Name', 'Rule Index', 'Action', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Set up progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Testing applications...", total=total_apps)

            # Loop through applications to test
            for app_name, app_info in apps_to_test:
                # Get default ports for this application
                default_ports = app_info.get('default-ports')

                # Format default ports for display
                ports_str = "N/A"
                if default_ports:
                    if isinstance(default_ports, list):
                        ports_str = ", ".join(default_ports)
                    else:
                        ports_str = str(default_ports)

                # Extract a valid port number from default ports
                port = _extract_port_number(default_ports)

                # Determine the default protocol (TCP or UDP)
                default_protocol = 6  # Default to TCP (protocol number 6)
                protocol_str = "TCP"  # For CSV output
                if default_ports and isinstance(default_ports, (str, list)):
                    ports_info = default_ports[0] if isinstance(default_ports, list) else default_ports
                    if isinstance(ports_info, str) and "udp/" in ports_info.lower():
                        default_protocol = 17  # UDP (protocol number 17)
                        protocol_str = "UDP"

                try:
                    # Test the application
                    result = panos_device.test_security_policy_match(
                        source=uid.SOURCE_IP_FOR_TESTING,
                        destination=default_dest_ip,
                        port=port,
                        protocol=default_protocol,  # Use the default protocol for the application
                        application=app_name,
                        from_zone=settings.ZONE_INSIDE,
                        to_zone=settings.ZONE_OUTSIDE,
                        show_all=False
                    )

                    # Process and write results to CSV
                    if result:
                        for rule in result:
                            action = rule.get('action', 'unknown')
                            name = rule.get('name', 'unknown')
                            index = rule.get('index', 'unknown')

                            # Write to CSV
                            writer.writerow({
                                'Application': app_name,
                                'Category': app_info.get('category', 'N/A'),
                                'Subcategory': app_info.get('subcategory', 'N/A'),
                                'Risk': app_info.get('risk', 'N/A'),
                                'Default Ports': ports_str,
                                'Chosen Port': port,
                                'Chosen Protocol': protocol_str,  # Using the determined protocol for testing
                                'Username': uid.MAPPED_USER or 'N/A',
                                'Group Name': uid.MAPPED_GROUP or 'N/A',
                                'Rule Name': name,
                                'Rule Index': index,
                                'Action': action,
                                'Description': _sanitize_text(app_info.get('description', 'N/A'))
                            })
                    else:
                        # No matching rule found
                        writer.writerow({
                            'Application': app_name,
                            'Category': app_info.get('category', 'N/A'),
                            'Subcategory': app_info.get('subcategory', 'N/A'),
                            'Risk': app_info.get('risk', 'N/A'),
                            'Default Ports': ports_str,
                            'Chosen Port': port,
                            'Chosen Protocol': protocol_str,  # Using the determined protocol for testing
                            'Username': uid.MAPPED_USER or 'N/A',
                            'Group Name': uid.MAPPED_GROUP or 'N/A',
                            'Rule Name': 'No matching rule',
                            'Rule Index': 'N/A',
                            'Action': 'N/A',
                            'Description': _sanitize_text(app_info.get('description', 'N/A'))
                        })

                except Exception as e:
                    # Handle errors
                    writer.writerow({
                        'Application': app_name,
                        'Category': app_info.get('category', 'N/A'),
                        'Subcategory': app_info.get('subcategory', 'N/A'),
                        'Risk': app_info.get('risk', 'N/A'),
                        'Default Ports': ports_str,
                        'Chosen Port': port,
                        'Chosen Protocol': protocol_str,  # Using the determined protocol for testing
                        'Username': uid.MAPPED_USER or 'N/A',
                        'Group Name': uid.MAPPED_GROUP or 'N/A',
                        'Rule Name': 'Error',
                        'Rule Index': 'N/A',
                        'Action': 'Error',
                        'Description': _sanitize_text(str(e))
                    })

                # Update progress bar
                progress.update(task, advance=1)

    console.print(f"[bold green]✓[/bold green] App-ID testing completed. Results saved to [bold]{csv_path}[/bold]")

    # Wait for Enter before returning to the menu
    input("\nPress Enter to return to the menu...")
