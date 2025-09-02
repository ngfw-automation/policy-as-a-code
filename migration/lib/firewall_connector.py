"""
Firewall connector module.
Handles firewall connections, authentication, and API operations.
"""
import sys
import os
from typing import Dict, List, Optional, Tuple
from getpass import getpass

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import panos.firewall
from lib.rich_output import console
from rich.status import Status
import settings


def get_firewall_credentials(default_firewall: str = '', default_user: str = 'admin') -> Tuple[str, str, str]:
    """
    Get firewall credentials from user input.
    
    Args:
        default_firewall: Default firewall address
        default_user: Default username
        
    Returns:
        Tuple of (firewall_address, username, password)
    """
    console.print("[bold blue]Firewall Connection Setup[/bold blue]")
    console.print("Specify the firewall with the current Gen2 policy already deployed.")
    console.print("It will be used to retrieve effective members of application groups.")
    console.print("")
    
    firewall = input(f'Firewall address  [default: {default_firewall}]:') or default_firewall
    api_user = input(f'Username          [default: {default_user}]:') or default_user
    api_pass = getpass('Password:')
    
    return firewall, api_user, api_pass


def initialize_firewall_connection(hostname: str, username: str, password: str) -> Optional[panos.firewall.Firewall]:
    """
    Initialize connection to the firewall.
    
    Args:
        hostname: Firewall hostname or IP address
        username: API username
        password: API password
        
    Returns:
        Firewall object if connection successful, None otherwise
    """
    try:
        with Status(f"[blue]Connecting to {hostname}...[/blue]", console=console):
            fw = panos.firewall.Firewall(hostname=hostname, api_username=username, api_password=password)
            fw.refresh_system_info()
        
        console.print(f"[green]Connected to {hostname} ({fw.platform}, {fw.version})[/green]")
        return fw
        
    except Exception as e:
        console.print(f"[red]Failed to connect to firewall {hostname}: {str(e)}[/red]")
        return None


def validate_firewall_connectivity(fw: panos.firewall.Firewall) -> bool:
    """
    Validate firewall connectivity by testing a simple API call.
    
    Args:
        fw: Firewall object
        
    Returns:
        True if connectivity is valid, False otherwise
    """
    try:
        # Test connectivity with a simple system info call
        fw.refresh_system_info()
        console.print("[green]Firewall connectivity validated[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Firewall connectivity validation failed: {str(e)}[/red]")
        return False


def get_application_group_members(fw: panos.firewall.Firewall, group_name: str) -> Optional[List[str]]:
    """
    Get members of a specific application group from the firewall.
    
    Args:
        fw: Firewall object
        group_name: Name of the application group
        
    Returns:
        List of application names in the group, or None if failed
    """
    try:
        result = fw.op(
            f'<show><applications><vsys>vsys1</vsys><list><member>{group_name}</member></list></applications></show>',
            cmd_xml=False,
            xml=False
        )
        
        if result.attrib['status'] == 'success':
            members = result.findall(".//applications/member")
            member_list = [member.text for member in members]
            return member_list
        else:
            console.print(f"[yellow]Request failed for application group: {group_name}[/yellow]")
            return None
            
    except Exception as e:
        console.print(f"[red]Error retrieving application group {group_name}: {str(e)}[/red]")
        return None


def get_application_groups(fw: panos.firewall.Firewall, categories: List[Dict]) -> Dict[str, List[str]]:
    """
    Get application groups for all managed categories.
    
    Args:
        fw: Firewall object
        categories: List of category dictionaries with 'Category' and 'Action' keys
        
    Returns:
        Dictionary mapping category names to lists of applications
    """
    app_group_dictionary = {}
    managed_categories = []
    non_managed_categories = []
    
    console.print("[bold blue]Generating application group dictionary:[/bold blue]")
    
    for entry in categories:
        category_name = entry['SubCategory']
        action = entry['Action']
        
        # Build lists of managed and non-managed categories
        if action == settings.APP_ACTION_MANAGE:
            managed_categories.append(category_name)
        elif action == settings.APP_ACTION_ALERT:
            non_managed_categories.append(category_name)
        
        # Process managed and alert categories
        if action in [settings.APP_ACTION_MANAGE, settings.APP_ACTION_ALERT]:
            application_group_name = f'APG-{category_name}'
            
            with Status(f"[blue]Processing {application_group_name}...[/blue]", console=console):
                member_list = get_application_group_members(fw, application_group_name)
            
            if member_list is not None and len(member_list) > 0:
                app_group_dictionary[category_name] = member_list
                console.print(f"[green]✓ {application_group_name:<30} ({len(member_list)} applications)[/green]")
                
                if settings.VERBOSE_OUTPUT:
                    console.print(f"[dim]  Applications: {', '.join(member_list[:10])}{'...' if len(member_list) > 10 else ''}[/dim]")
            elif member_list is not None and len(member_list) == 0:
                console.print(f"[yellow]⚠ {application_group_name:<30} (empty group)[/yellow]")
            else:
                console.print(f"[red]✗ {application_group_name:<30} (failed to retrieve)[/red]")
    
    console.print(f"[green]Application group dictionary generation completed ({len(app_group_dictionary)} groups processed)[/green]")
    return app_group_dictionary, managed_categories, non_managed_categories


def test_firewall_connection() -> Optional[panos.firewall.Firewall]:
    """
    Interactive function to test firewall connection.
    
    Returns:
        Firewall object if connection successful, None otherwise
    """
    console.print("[bold blue]Testing Firewall Connection[/bold blue]")
    
    # Get credentials
    hostname, username, password = get_firewall_credentials()
    
    if not hostname:
        console.print("[red]Firewall hostname is required[/red]")
        return None
    
    # Initialize connection
    fw = initialize_firewall_connection(hostname, username, password)
    
    if fw is None:
        return None
    
    # Validate connectivity
    if not validate_firewall_connectivity(fw):
        return None
    
    console.print("[green]Firewall connection test successful[/green]")
    return fw


def get_firewall_info(fw: panos.firewall.Firewall) -> Dict[str, str]:
    """
    Get basic information about the connected firewall.
    
    Args:
        fw: Firewall object
        
    Returns:
        Dictionary containing firewall information
    """
    try:
        return {
            'hostname': fw.hostname,
            'platform': fw.platform,
            'version': fw.version,
            'serial': getattr(fw, 'serial', 'Unknown'),
            'model': getattr(fw, 'model', 'Unknown')
        }
    except Exception as e:
        console.print(f"[red]Error retrieving firewall info: {str(e)}[/red]")
        return {
            'hostname': fw.hostname if hasattr(fw, 'hostname') else 'Unknown',
            'platform': 'Unknown',
            'version': 'Unknown',
            'serial': 'Unknown',
            'model': 'Unknown'
        }


def display_firewall_info(fw: panos.firewall.Firewall) -> None:
    """
    Display firewall information in a formatted way.
    
    Args:
        fw: Firewall object
    """
    info = get_firewall_info(fw)
    
    console.print("[bold blue]Firewall Information:[/bold blue]")
    console.print(f"[blue]Hostname:[/blue] {info['hostname']}")
    console.print(f"[blue]Platform:[/blue] {info['platform']}")
    console.print(f"[blue]Version:[/blue] {info['version']}")
    console.print(f"[blue]Serial:[/blue] {info['serial']}")
    console.print(f"[blue]Model:[/blue] {info['model']}")