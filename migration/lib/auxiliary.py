"""
Auxiliary functions module for traffic log analysis.
Contains common utilities, user interaction functions, and menu system.
"""
import sys
import os
from typing import Optional, Dict, List

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from lib.rich_output import console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
import panos.firewall
import settings


def display_banner() -> None:
    """Display the application banner."""
    banner_text = Text()
    banner_text.append("Traffic Log Analysis Tool", style="bold blue")
    banner_text.append("\n")
    banner_text.append("Analyzes firewall traffic logs against policy configurations", style="dim")
    
    banner_panel = Panel(
        banner_text,
        title="[bold green]Migration Tool[/bold green]",
        border_style="green",
        padding=(1, 2)
    )
    
    console.print(banner_panel)
    console.print("")


def display_menu() -> int:
    """
    Display the main menu and get user choice.
    
    Returns:
        User's menu choice as integer
    """
    menu_options = [
        "1. Analyze Application Traffic",
        "2. Analyze URL Traffic", 
        "3. Analyze Both Traffic Types",
        "4. Configure Firewall Settings",
        "5. View Analysis Results",
        "6. Export Results",
        "7. Test Firewall Connection",
        "8. Exit"
    ]
    
    menu_table = Table(show_header=False, box=None, padding=(0, 2))
    menu_table.add_column("Option", style="cyan", no_wrap=True)
    
    for option in menu_options:
        menu_table.add_row(option)
    
    menu_panel = Panel(
        menu_table,
        title="[bold blue]Main Menu[/bold blue]",
        border_style="blue"
    )
    
    console.print(menu_panel)
    
    while True:
        try:
            choice = input("\nSelect an option [1-8]: ").strip()
            choice_int = int(choice)
            if 1 <= choice_int <= 8:
                return choice_int
            else:
                console.print("[red]Please enter a number between 1 and 8[/red]")
        except ValueError:
            console.print("[red]Please enter a valid number[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return 8


def get_user_confirmation(message: str, default: bool = False) -> bool:
    """
    Get yes/no confirmation from user.
    
    Args:
        message: Confirmation message to display
        default: Default value if user just presses Enter
        
    Returns:
        True if user confirms, False otherwise
    """
    default_text = "Y/n" if default else "y/N"
    prompt = f"{message} [{default_text}]: "
    
    try:
        response = input(prompt).strip().lower()
        if not response:
            return default
        return response in ['y', 'yes', 'true', '1']
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return False


def get_file_path(prompt: str, default: str = "") -> str:
    """
    Get file path from user with validation.
    
    Args:
        prompt: Prompt message to display
        default: Default file path
        
    Returns:
        File path entered by user
    """
    while True:
        try:
            if default:
                path = input(f"{prompt} [default: {default}]: ").strip() or default
            else:
                path = input(f"{prompt}: ").strip()
            
            if path:
                return path
            elif default:
                return default
            else:
                console.print("[red]File path is required[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return default if default else ""


def display_configuration_menu() -> int:
    """
    Display configuration menu and get user choice.
    
    Returns:
        User's menu choice as integer
    """
    config_options = [
        "1. Set Traffic Report Filenames",
        "2. Set Output Filenames", 
        "3. Configure Firewall Connection",
        "4. View Current Configuration",
        "5. Reset to Defaults",
        "6. Back to Main Menu"
    ]
    
    config_table = Table(show_header=False, box=None, padding=(0, 2))
    config_table.add_column("Option", style="cyan", no_wrap=True)
    
    for option in config_options:
        config_table.add_row(option)
    
    config_panel = Panel(
        config_table,
        title="[bold blue]Configuration Menu[/bold blue]",
        border_style="blue"
    )
    
    console.print(config_panel)
    
    while True:
        try:
            choice = input("\nSelect an option [1-6]: ").strip()
            choice_int = int(choice)
            if 1 <= choice_int <= 6:
                return choice_int
            else:
                console.print("[red]Please enter a number between 1 and 6[/red]")
        except ValueError:
            console.print("[red]Please enter a valid number[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return 6


def display_analysis_menu() -> int:
    """
    Display analysis type selection menu.
    
    Returns:
        User's menu choice as integer
    """
    analysis_options = [
        "1. Applications Only",
        "2. URLs Only",
        "3. Both Applications and URLs",
        "4. Back to Main Menu"
    ]
    
    analysis_table = Table(show_header=False, box=None, padding=(0, 2))
    analysis_table.add_column("Option", style="cyan", no_wrap=True)
    
    for option in analysis_options:
        analysis_table.add_row(option)
    
    analysis_panel = Panel(
        analysis_table,
        title="[bold blue]Analysis Type[/bold blue]",
        border_style="blue"
    )
    
    console.print(analysis_panel)
    
    while True:
        try:
            choice = input("\nSelect analysis type [1-4]: ").strip()
            choice_int = int(choice)
            if 1 <= choice_int <= 4:
                return choice_int
            else:
                console.print("[red]Please enter a number between 1 and 4[/red]")
        except ValueError:
            console.print("[red]Please enter a valid number[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return 4


def display_current_configuration(config: Dict) -> None:
    """
    Display current configuration settings.
    
    Args:
        config: Configuration dictionary
    """
    config_info = f"""[blue]Traffic Report Files:[/blue]
  Application: {config.get('traffic_filename', 'Not set')}
  URL: {config.get('url_filename', 'Not set')}

[blue]Output Files:[/blue]
  Application Results: {config.get('app_output_filename', 'Not set')}
  URL Results: {config.get('url_output_filename', 'Not set')}

[blue]Firewall Connection:[/blue]
  Hostname: {config.get('firewall_hostname', 'Not set')}
  Username: {config.get('firewall_username', 'Not set')}
  Connected: {'Yes' if config.get('firewall_connected', False) else 'No'}"""
    
    config_panel = Panel(
        config_info,
        title="[bold blue]Current Configuration[/bold blue]",
        border_style="blue"
    )
    
    console.print(config_panel)


def initialize_firewall() -> Optional[panos.firewall.Firewall]:
    """
    Initialize firewall connection with user interaction.
    
    Returns:
        Firewall object if successful, None otherwise
    """
    from migration.lib.firewall_connector import get_firewall_credentials, initialize_firewall_connection
    
    console.print("[bold blue]Firewall Connection Required[/bold blue]")
    console.print("A firewall connection is needed to retrieve application group information.")
    
    if not get_user_confirmation("Connect to firewall now?", True):
        console.print("[yellow]Firewall connection skipped. Some features may not be available.[/yellow]")
        return None
    
    # Get credentials
    hostname, username, password = get_firewall_credentials()
    
    if not hostname:
        console.print("[red]Firewall hostname is required[/red]")
        return None
    
    # Initialize connection
    fw = initialize_firewall_connection(hostname, username, password)
    
    if fw is None:
        console.print("[red]Failed to connect to firewall[/red]")
        return None
    
    return fw


def display_error(message: str, details: Optional[str] = None) -> None:
    """
    Display error message in a formatted panel.
    
    Args:
        message: Main error message
        details: Optional detailed error information
    """
    error_text = f"[red]{message}[/red]"
    if details:
        error_text += f"\n[dim]{details}[/dim]"
    
    error_panel = Panel(
        error_text,
        title="[bold red]Error[/bold red]",
        border_style="red"
    )
    
    console.print(error_panel)


def display_success(message: str, details: Optional[str] = None) -> None:
    """
    Display success message in a formatted panel.
    
    Args:
        message: Main success message
        details: Optional detailed information
    """
    success_text = f"[green]{message}[/green]"
    if details:
        success_text += f"\n[dim]{details}[/dim]"
    
    success_panel = Panel(
        success_text,
        title="[bold green]Success[/bold green]",
        border_style="green"
    )
    
    console.print(success_panel)


def display_warning(message: str, details: Optional[str] = None) -> None:
    """
    Display warning message in a formatted panel.
    
    Args:
        message: Main warning message
        details: Optional detailed information
    """
    warning_text = f"[yellow]{message}[/yellow]"
    if details:
        warning_text += f"\n[dim]{details}[/dim]"
    
    warning_panel = Panel(
        warning_text,
        title="[bold yellow]Warning[/bold yellow]",
        border_style="yellow"
    )
    
    console.print(warning_panel)


def display_info(message: str, details: Optional[str] = None) -> None:
    """
    Display informational message in a formatted panel.
    
    Args:
        message: Main information message
        details: Optional detailed information
    """
    info_text = f"[blue]{message}[/blue]"
    if details:
        info_text += f"\n[dim]{details}[/dim]"
    
    info_panel = Panel(
        info_text,
        title="[bold blue]Information[/bold blue]",
        border_style="blue"
    )
    
    console.print(info_panel)


def wait_for_user() -> None:
    """Wait for user to press Enter to continue."""
    try:
        input("\nPress Enter to continue...")
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")


def clear_screen() -> None:
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_default_configuration() -> Dict:
    """
    Get default configuration settings.
    
    Returns:
        Dictionary containing default configuration
    """
    return {
        'traffic_filename': 'traffic_report_app.csv',
        'url_filename': 'traffic_report_url.csv',
        'app_output_filename': 'traffic_report_app_with_verdicts.csv',
        'url_output_filename': 'traffic_report_url_with_verdicts.csv',
        'firewall_hostname': '',
        'firewall_username': 'admin',
        'firewall_connected': False,
        'requirements_path': '../requirements'
    }


def validate_configuration(config: Dict) -> List[str]:
    """
    Validate configuration settings.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        List of validation error messages
    """
    errors = []
    
    if not config.get('traffic_filename'):
        errors.append("Traffic report filename is not set")
    
    if not config.get('url_filename'):
        errors.append("URL report filename is not set")
    
    if not config.get('app_output_filename'):
        errors.append("Application output filename is not set")
    
    if not config.get('url_output_filename'):
        errors.append("URL output filename is not set")
    
    return errors


def display_help() -> None:
    """Display help information about the tool."""
    help_text = """This tool analyzes firewall traffic logs against policy configurations to help understand the impact of applying Gen2 policies.

[bold blue]Prerequisites:[/bold blue]
• Traffic report CSV files generated from PAN-OS device
• Access to firewall with deployed Gen2 policy
• Category requirement files in ../requirements/ directory

[bold blue]Workflow:[/bold blue]
1. Configure firewall connection settings
2. Load traffic report files
3. Connect to firewall to retrieve application groups
4. Analyze traffic against policy rules
5. Export results to CSV files

[bold blue]Output Files:[/bold blue]
• Application analysis results with verdicts
• URL analysis results with verdicts
• Optional summary report

[bold blue]File Formats:[/bold blue]
Traffic reports should contain:
• Application report: Source User, Application, App Sub Category, Bytes
• URL report: Source User, URL, Category, Count"""
    
    help_panel = Panel(
        help_text,
        title="[bold green]Help - Traffic Log Analysis Tool[/bold green]",
        border_style="green"
    )
    
    console.print(help_panel)