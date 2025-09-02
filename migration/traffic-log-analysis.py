#!/usr/bin/env python3
"""
Traffic Log Analysis Tool - Simplified CLI Version
Analyzes firewall traffic logs against policy configurations to help understand
the impact of applying Gen2 policies.

This simplified version uses CLI questions instead of menus.
"""
import sys
import os
from typing import Optional, Dict, List, Tuple

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from lib.rich_output import console
from migration.lib import auxiliary as aux
from migration.lib import traffic_parser as parser
from migration.lib import firewall_connector as fw_conn
from migration.lib import policy_analyzer as analyzer
from migration.lib import report_generator as reporter
from lib.category_parser import parse_app_categories, parse_url_categories
import settings

# Enable rich tracebacks if configured
if settings.RICH_TRACEBACKS:
    from rich.traceback import install
    install(show_locals=settings.RICH_TRACEBACKS_SHOW_VARS)
    if settings.VERBOSE_OUTPUT:
        console.print(f"[dim]Verbose mode has been enabled[/dim]")
        console.print(f"[dim]Rich traceback has been enabled[/dim]")

# Enable debug output if configured
if settings.DEBUG_OUTPUT:
    import logging
    import http.client as http_client
    import requests
    
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig(level=logging.DEBUG)
    requests.packages.urllib3.add_stderr_logger(level=logging.DEBUG)
    console.print(f"[bold red]Debug mode has been enabled[/bold red]")


def get_user_input(prompt: str, default: str = "") -> str:
    """Get user input with optional default value."""
    try:
        if default:
            response = input(f"{prompt} [default: {default}]: ").strip()
            return response if response else default
        else:
            response = input(f"{prompt}: ").strip()
            return response
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)


def get_password(prompt: str) -> str:
    """Get password input without echoing."""
    import getpass
    try:
        return getpass.getpass(f"{prompt}: ")
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no confirmation from user."""
    default_text = "Y/n" if default else "y/N"
    try:
        response = input(f"{prompt} [{default_text}]: ").strip().lower()
        if not response:
            return default
        return response in ['y', 'yes', 'true', '1']
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)


def validate_file_exists(filepath: str) -> bool:
    """Check if file exists and display appropriate message."""
    if os.path.exists(filepath):
        console.print(f"[green]✓[/green] Found file: {filepath}")
        return True
    else:
        console.print(f"[yellow]⚠[/yellow] File not found: {filepath}")
        return False


def main() -> None:
    """Main application entry point with simplified CLI."""
    # Display banner
    aux.display_banner()
    
    console.print("[green]Traffic Log Analysis Tool - Simplified CLI[/green]")
    console.print("[dim]This tool will guide you through the analysis process with a series of questions.[/dim]\n")
    
    # Initialize configuration with defaults
    config = aux.get_default_configuration()
    
    # Load category requirements at startup
    console.print("[blue]Initializing...[/blue]")
    try:
        # Use absolute paths to ensure files are found when running from migration directory
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        app_categories_path = os.path.join(project_root, settings.APP_CATEGORIES_REQUIREMENTS_FILENAME)
        url_categories_path = os.path.join(project_root, settings.URL_CATEGORIES_REQUIREMENTS_FILENAME)
        
        app_categories = parse_app_categories(app_categories_path)
        url_categories = parse_url_categories(url_categories_path)
        
        if app_categories is None or url_categories is None:
            console.print("[red]Failed to load category requirements files[/red]")
            return
            
        console.print("[green]✓[/green] Category requirements loaded successfully\n")
    except Exception as e:
        aux.display_error("Failed to initialize", f"Cannot load category requirements: {str(e)}")
        return
    
    # Step 1: Firewall Configuration
    console.print("[bold blue]Step 1: Firewall Configuration[/bold blue]")
    console.print("Please provide your firewall connection details:")
    
    hostname = get_user_input("Firewall hostname or IP address")
    if not hostname:
        console.print("[red]Firewall hostname is required[/red]")
        return
    
    username = get_user_input("Username", config['firewall_username'])
    password = get_password("Password")
    
    config['firewall_hostname'] = hostname
    config['firewall_username'] = username
    
    # Test firewall connection
    console.print("\n[blue]Testing firewall connection...[/blue]")
    try:
        firewall = fw_conn.initialize_firewall_connection(hostname, username, password)
        if not firewall:
            console.print("[red]Failed to connect to firewall. Please check your credentials and try again.[/red]")
            return
        console.print("[green]✓[/green] Firewall connection successful\n")
        config['firewall_connected'] = True
    except Exception as e:
        console.print(f"[red]Firewall connection failed: {str(e)}[/red]")
        return
    
    # Step 2: Input Files Configuration
    console.print("[bold blue]Step 2: Input Files Configuration[/bold blue]")
    console.print("Please specify the traffic report files to analyze:")
    
    # Application traffic file
    app_file = get_user_input("Application traffic report file", config['traffic_filename'])
    config['traffic_filename'] = app_file
    validate_file_exists(app_file)
    
    # URL traffic file
    url_file = get_user_input("URL traffic report file", config['url_filename'])
    config['url_filename'] = url_file
    validate_file_exists(url_file)
    
    # Step 3: Output Files Configuration
    console.print("\n[bold blue]Step 3: Output Files Configuration[/bold blue]")
    console.print("Specify where to save the analysis results:")
    
    app_output = get_user_input("Application analysis output file", config['app_output_filename'])
    config['app_output_filename'] = app_output
    
    url_output = get_user_input("URL analysis output file", config['url_output_filename'])
    config['url_output_filename'] = url_output
    
    # Step 4: Analysis Type Selection
    console.print("\n[bold blue]Step 4: Analysis Type Selection[/bold blue]")
    console.print("Please specify which types of analysis to perform:")
    
    analyze_apps = get_yes_no("Analyze application traffic?", True)
    analyze_urls = get_yes_no("Analyze URL traffic?", True)
    
    if not analyze_apps and not analyze_urls:
        console.print("[yellow]No analysis type selected. At least one analysis type is required.[/yellow]")
        return
    
    # Step 4.5: Application Analysis Method Selection
    use_synthetic_testing = False
    source_ip_for_testing = None
    
    if analyze_apps:
        console.print("\n[bold blue]Step 4.5: Application Analysis Method Selection[/bold blue]")
        console.print("Choose the application analysis method:")
        console.print("1. Static rule-based analysis (faster, uses predefined business rules)")
        console.print("2. Synthetic testing (slower, tests against actual firewall policy)")
        
        while True:
            method_choice = input("\nChoose method (1 or 2): ").strip()
            if method_choice == "1":
                console.print("[green]✓[/green] Using static rule-based analysis")
                use_synthetic_testing = False
                break
            elif method_choice == "2":
                console.print("[green]✓[/green] Using synthetic testing approach")
                use_synthetic_testing = True
                break
            else:
                console.print("[red]Invalid choice. Please enter 1 or 2.[/red]")
    
    # Step 5: Perform Analysis
    console.print("\n[bold blue]Step 5: Performing Analysis[/bold blue]")
    
    app_results = None
    url_results = None
    
    try:
        if analyze_apps:  # Application analysis
            console.print("[blue]Analyzing application traffic...[/blue]")
            
            # Load and parse application traffic
            app_traffic = parser.parse_traffic_report(config['traffic_filename'])
            if not app_traffic:
                console.print("[red]Failed to load application traffic data[/red]")
                return
            
            # Perform analysis based on selected method
            if use_synthetic_testing:
                # For synthetic testing, we don't need application groups
                # Configure source IP for synthetic testing
                source_ip_for_testing = analyzer.determine_source_ip_for_testing(app_traffic)
                
                # Perform synthetic analysis
                app_results = analyzer.analyze_application_traffic_synthetic(
                    app_traffic, firewall, source_ip_for_testing
                )
            else:
                # Get application groups from firewall for static analysis
                app_group_dictionary, managed_categories, non_managed_categories = fw_conn.get_application_groups(firewall, app_categories)
                if not app_group_dictionary:
                    console.print("[red]Failed to retrieve application groups from firewall[/red]")
                    return
                
                # Perform static rule-based analysis
                app_results = analyzer.analyze_application_traffic(
                    app_traffic, app_group_dictionary, managed_categories, non_managed_categories, app_categories
                )
            
            console.print(f"[green]✓[/green] Application analysis completed ({len(app_results)} records)")
        
        if analyze_urls:  # URL analysis
            console.print("[blue]Analyzing URL traffic...[/blue]")
            
            # Load and parse URL traffic
            url_traffic = parser.parse_url_report(config['url_filename'])
            if not url_traffic:
                console.print("[red]Failed to load URL traffic data[/red]")
                return
            
            # Categorize URL categories to get required parameters
            managed_url_categories, non_managed_url_categories, blocked_url_categories, paused_url_categories = analyzer.categorize_url_categories(url_categories)
            
            # Perform analysis
            url_results = analyzer.analyze_url_traffic(
                url_traffic, managed_url_categories, non_managed_url_categories, 
                blocked_url_categories, paused_url_categories, url_categories
            )
            console.print(f"[green]✓[/green] URL analysis completed ({len(url_results)} records)")
        
    except Exception as e:
        console.print(f"[red]Analysis failed: {str(e)}[/red]")
        if settings.DEBUG_OUTPUT:
            raise
        return
    
    # Step 6: Export Results
    console.print("\n[bold blue]Step 6: Exporting Results[/bold blue]")
    
    try:
        if app_results:
            reporter.save_app_analysis_results(app_results, config['app_output_filename'])
            console.print(f"[green]✓[/green] Application results exported to: {config['app_output_filename']}")
        
        if url_results:
            reporter.save_url_analysis_results(url_results, config['url_output_filename'])
            console.print(f"[green]✓[/green] URL results exported to: {config['url_output_filename']}")
        
    except Exception as e:
        console.print(f"[red]Export failed: {str(e)}[/red]")
        if settings.DEBUG_OUTPUT:
            raise
        return
    
    # Step 7: Display Summary
    console.print("\n[bold green]Analysis Complete![/bold green]")
    
    if app_results or url_results:
        console.print("\n[bold blue]Summary:[/bold blue]")
        if app_results:
            console.print(f"• Application records analyzed: {len(app_results)}")
        if url_results:
            console.print(f"• URL records analyzed: {len(url_results)}")
        
        # Show preview of results
        if get_yes_no("\nWould you like to see a preview of the results?", True):
            reporter.display_results_preview(app_results or [], url_results or [])
    
    console.print("\n[green]Thank you for using Traffic Log Analysis Tool![/green]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Application interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        if settings.DEBUG_OUTPUT:
            raise
        sys.exit(1)