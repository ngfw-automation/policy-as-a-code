"""
Main entry point for Policy-as-a-Code deployment application.

This module provides an interactive interface for deploying firewall policies to PAN-OS devices.
It supports both Panorama and standalone firewall deployments with the following capabilities:

- Interactive menu-driven deployment selection
- Credential management with optional cookie-based persistence
- Template generation and validation for application and URL categories
- Business requirements parsing and validation
- Category cross-referencing and warning system
- Comprehensive error handling and user input validation
- Policy deployment orchestration via the build_policy module

The module serves as the primary user interface for the policy deployment system,
handling user interactions, configuration validation, and coordinating with
specialized modules for actual policy construction and deployment.
"""

import time
import sys
import re
import os
from getpass import getpass

from rich.panel import Panel
from lib.rich_output import console

from panos.panorama import Panorama
from panos.firewall import Firewall
import json

from lib.template_generator import generate_app_categories_template, generate_url_categories_template
from lib.category_parser    import parse_app_categories, parse_url_categories
from lib.build_policy   import build_policy
from lib.auxiliary_functions import load_menu_options, display_menu, get_user_choice

import settings

# =================================================================================================================
# GLOBAL VARIABLES AND CONFIGURATION SETUP
# =================================================================================================================

# Global variables for menu state management
menu_options = None
default_choice = None

# =================================================================================================================
# RICH TRACEBACK CONFIGURATION
# =================================================================================================================

# Configure Rich tracebacks for enhanced error reporting if enabled
if settings.RICH_TRACEBACKS:
    from rich.traceback import install
    install(show_locals=settings.RICH_TRACEBACKS_SHOW_VARS)
    if settings.VERBOSE_OUTPUT:
        console.print(f"[dim]Verbose mode has been enabled[/dim]")
        console.print(f"[dim]Rich traceback has been enabled[/dim]")

# =================================================================================================================
# HTTP DEBUG CONFIGURATION
# =================================================================================================================

# Enable comprehensive HTTP debugging when DEBUG_OUTPUT is active
# This provides detailed logging of all HTTP requests/responses for troubleshooting
if settings.DEBUG_OUTPUT:
    import logging                     # Python’s standard logging framework
    import http.client as http_client  # low-level HTTP protocol client
    import requests                    # User-friendly HTTP library built on urllib3

    # 1) Enable raw socket-level dumps of everything:
    #    - Headers and bodies for each request you send
    #    - Headers and bodies for each response you receive
    #    This prints directly to stdout.
    http_client.HTTPConnection.debuglevel = 1

    # 2) Initialize the root logger so DEBUG messages are processed.
    #    Without this, even if urllib3 emits DEBUG logs, you won’t see them.
    logging.basicConfig(level=logging.DEBUG)

    # 3) Turn on DEBUG logging in urllib3 (used internally by requests):
    #    - Prints request lines (e.g. “> GET /api… HTTP/1.1”)
    #    - Prints response status (e.g. “< HTTP/1.1 200 OK”)
    #    - Shows connection pooling details, retries, etc.
    requests.packages.urllib3.add_stderr_logger(level=logging.DEBUG)

    console.print(f"[bold red]Debug mode has been enabled[/bold red]")


def deploy_policy(selected_option, arguments, target_environment, panos_address, deployment_type, 
               panorama_device_group=None, panorama_template=None, firewall_vsys=None) -> int:
    """
    Orchestrates the complete policy deployment process to a specified PAN-OS target.

    This function handles the entire deployment workflow including credential management,
    device connection establishment, requirements validation, template generation,
    category cross-referencing, and policy building coordination. It provides comprehensive
    error handling and user confirmation prompts throughout the process.
    
    FUNCTION RELATIONSHIPS:
    - main(): Handles user interface, menu selection, and calls deploy_policy()
    - deploy_policy(): Manages deployment workflow, validation, and calls build_policy()  
    - build_policy(): Performs actual policy construction on the PAN-OS device

    Args:
        selected_option (str): The user-selected deployment option name from the menu.
        arguments (dict): Dictionary containing deployment configuration parameters
            including target environment, device addresses, and deployment-specific settings.
        target_environment (str): The target environment identifier (e.g., 'prod', 'lab', 'dev')
            used for environment-specific object naming and EDL URL substitution.
        panos_address (str): The IP address or hostname of the target PAN-OS device.
        deployment_type (str): The type of PAN-OS deployment target.
            Supported values: 'panorama' or 'firewall'.
        panorama_device_group (str, optional): The Panorama device group name where
            policies will be deployed. Required when deployment_type is 'panorama'.
            Defaults to None.
        panorama_template (str, optional): The Panorama template name where custom
            objects will be imported. Required when deployment_type is 'panorama'.
            Defaults to None.
        firewall_vsys (str, optional): The firewall virtual system name for policy
            deployment. Required when deployment_type is 'firewall'. Defaults to None.

    Returns:
        int: Exit code indicating the deployment result:
            - 0: Successful deployment completion
            - 1: Deployment failed due to error (invalid credentials, missing files,
                 parsing errors, or user abort)

    Raises:
        FileNotFoundError: When required category requirements files are missing.
        json.JSONDecodeError: When cookie file contains invalid JSON data.
        ConnectionError: When unable to establish connection to PAN-OS device.
        
    Note:
        This function performs extensive validation of business requirements files
        and provides interactive warnings for missing categories. The deployment
        process includes comprehensive timing measurements and detailed progress reporting.
    """
    console.print("\nProceeding with policy deployment...")

    # =================================================================================================================
    # CREDENTIAL MANAGEMENT AND AUTHENTICATION
    # =================================================================================================================

    # Obtain credentials for PAN-OS device authentication
    # TODO: retrieve creds from ENV if executed with command line parameters as part of a CI/CD pipeline
    
    # Read the default admin username from Settings configuration
    default_admin_username = settings.DEFAULT_ADMIN_USERNAME
    
    # Implement cookie-based credential persistence for improved user experience
    # Cookie stores last username and menu choice to reduce repetitive input
    if settings.USE_COOKIE:
        try:
            with open(settings.COOKIE_FILENAME, 'r') as f:
                cookie = json.load(f)
            # Override default username with stored value if available
            if cookie['admin_username'] is not None:
                default_admin_username = cookie['admin_username']
        except FileNotFoundError:
            # Initialize cookie file with default values when missing
            cookie = json.dumps({"admin_username": settings.DEFAULT_ADMIN_USERNAME}, indent=4)
            with open(settings.COOKIE_FILENAME, 'w') as f:
                f.write(cookie)

    # Interactive username collection with comprehensive validation
    while True:
        admin_username = input(f'Enter username [`{default_admin_username}`]: ').lower() or default_admin_username
        # Validate username meets security and compatibility requirements
        # PAN-OS has specific constraints on acceptable username formats
        if not re.match(r'^[a-z0-9_.-]+$', admin_username):
            console.print("[bold red]Error:[/bold red] Username can only contain lowercase letters, numbers, underscores, dashes, and dots.")
            continue
        # Minimum username length requirement for security compliance
        if len(admin_username) < 3:
            console.print("[bold red]Error:[/bold red] Username must be at least 3 characters long.")
            continue
        break

    # Secure password collection with validation
    admin_password = getpass("Enter password: ")
    # Validate critical input parameters before proceeding
    # Empty passwords pose security risks and will cause authentication failures
    if not admin_password:
        console.print("[bold red]Error:[/bold red] Password cannot be empty.")
        return 1

    # Update cookie with current session information for future convenience
    if settings.USE_COOKIE:
        cookie = json.dumps({"admin_username": admin_username, "last_menu_choice": selected_option}, indent=4)
        with open(settings.COOKIE_FILENAME, 'w') as f:
            f.write(cookie)

    # =================================================================================================================
    # DEVICE CONNECTION AND TIMING
    # =================================================================================================================
    
    # Start execution timing (no interactive prompts expected after this point)
    start_time = time.time()

    # Create appropriate PANOS device object based on deployment type
    # Handle different deployment scenarios based on device type
    # Panorama deployments require device group and template specification
    # Firewall deployments use VSYS for both policy container and template
    if deployment_type == 'panorama':
        panos_device = Panorama(hostname=panos_address, api_username=admin_username, api_password=admin_password)
    elif deployment_type == 'firewall':
        panos_device = Firewall(hostname=panos_address, api_username=admin_username, api_password=admin_password, vsys="shared")
    else:
        print(f"!!! Unknown deployment type ({deployment_type}). Aborting script execution...")
        return 1

    console.print('\nProceeding with policy provisioning to the specified device...')

    # =================================================================================================================
    # CATEGORY TEMPLATE GENERATION AND VALIDATION
    # =================================================================================================================
    
    # Generate category templates from live device data for validation purposes
    # NOTE: These are business requirement templates, not Panorama configuration templates!
    # Pull all categories from the actual device to perform cross-referencing validation
    # This helps track changes made by vendor via dynamic content updates
    current_app_categories = generate_app_categories_template(panos_device)
    current_url_categories = generate_url_categories_template(panos_device)

    # These templates then need to be manually cloned (copied) to the files called
    # as defined in 'settings.app_categories_filename' and 'settings.url_categories_filename'.
    # Then required categories need to be labelled as managed.

    # Now we retrieve APP & URL metadata from the files created above.
    # This metadata contains the actual business requirements
    app_categories_requirements = parse_app_categories(settings.APP_CATEGORIES_REQUIREMENTS_FILENAME)
    url_categories_requirements = parse_url_categories(settings.URL_CATEGORIES_REQUIREMENTS_FILENAME)

    # Check if required files exist and provide clear error messages
    if not os.path.exists(settings.APP_CATEGORIES_REQUIREMENTS_FILENAME):
        console.print(
            f"[bold red]Error:[/bold red] File `{settings.APP_CATEGORIES_REQUIREMENTS_FILENAME}` does not exist.\n"
            f"Create it by cloning the template and amending its contents according to your business requirements.")
        return 1

    if not os.path.exists(settings.URL_CATEGORIES_REQUIREMENTS_FILENAME):
        console.print(
            f"[bold red]Error:[/bold red] File `{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}` does not exist.\n"
            f"Create it by cloning the template and amending its contents according to your business requirements.")
        return 1

    # If files exist but parsing failed
    if app_categories_requirements is None or url_categories_requirements is None:
        console.print(
            f"[bold red]Error:[/bold red] Failed to parse the requirements files.\n"
            f"Make sure the files `{settings.APP_CATEGORIES_REQUIREMENTS_FILENAME}` and "
            f"`{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}` are properly formatted.")
        return 1

    a_category_is_missing = 0
    # Now we cross-reference the list of categories specified in the app requirements file
    # with the current list of available categories on our PAN-OS device
    for current_category in current_app_categories:
        match_found = False
        for requirements_category in app_categories_requirements:
            if current_category == requirements_category['SubCategory']:
                match_found = True
        if not match_found:
            a_category_is_missing += 1
            console.print(Panel.fit(f'The App-ID subcategory "[yellow]{current_category}[/yellow]" is not '
                                f'mentioned in the list of requirements.\nApplications from this subcategory '
                                f'will be handled by the policy as non-sanctioned ([bold]blocked[/bold])',
                                title="WARNING", border_style="red"))

    # Now we cross-reference the list of categories specified in the app requirements file
    # with the current list of available categories on our PAN-OS device
    for current_category in current_url_categories:
        if current_category not in ["high-risk", "medium-risk", "low-risk"]:
            match_found = False
            for requirements_category in url_categories_requirements:
                if current_category == requirements_category['Category']:
                    match_found = True
            if not match_found:
                a_category_is_missing += 1
                console.print(Panel.fit(f'The URL category "[yellow]{current_category}[/yellow]" is not '
                                    f'mentioned in the list of requirements.\nURLs from this category will '
                                    f'be [bold]ALLOWED[/bold] and [bold]NOT LOGGED[/bold] - make sure this is a desired behaviour',
                                    title="WARNING", border_style="red"))

    if a_category_is_missing > 0 and not settings.SUPPRESS_WARNINGS:
        # Ask for confirmation with clear instructions and validation
        while True:
            choice = input(f"\nReview the warning(s) above and enter 'OK' to Continue or 'CANCEL' to Abort script execution: ")
            choice = choice.strip().upper()
            if choice == 'OK':
                break
            elif choice == 'CANCEL':
                console.print("[bold yellow]Operation aborted by user.[/bold yellow]")
                return 0
            else:
                console.print("[bold red]Invalid input.[/bold red] Please enter 'OK' to continue or 'CANCEL' to abort.")
                continue

        # If we get here, the user confirmed with 'OK'
        print("\nProceeding with policy deployment...")
        # Build the actual policy using required APP/URL customizations
        # =======================================================================================================
        build_policy(panos_device     = panos_device,
                     policy_container = panorama_device_group if isinstance(panos_device, Panorama) else firewall_vsys,
                     policy_template  = panorama_template     if isinstance(panos_device, Panorama) else firewall_vsys,
                     app_categories_requirements = app_categories_requirements,
                     url_categories_requirements = url_categories_requirements,
                     current_url_categories      = current_url_categories,
                     target_environment          = target_environment)
        # =======================================================================================================
    else:
        build_policy(panos_device     = panos_device,
                     policy_container = panorama_device_group if isinstance(panos_device, Panorama) else firewall_vsys,
                     policy_template  = panorama_template     if isinstance(panos_device, Panorama) else firewall_vsys,
                     app_categories_requirements = app_categories_requirements,
                     url_categories_requirements = url_categories_requirements,
                     current_url_categories      = current_url_categories,
                     target_environment          = target_environment)

    end_time = time.time()
    elapsed_time = int(end_time - start_time)
    print(f'Execution time: {elapsed_time} seconds')
    return 0


def main(**kwargs) -> int:
    """
    Primary entry point for the Policy-as-a-Code deployment application.

    This function orchestrates the complete user interaction workflow for policy deployment,
    including menu presentation, option selection, target configuration, and deployment
    execution. It handles both interactive menu-driven operation and command-line argument
    processing (future implementation).

    The function manages:
    - Menu option loading and validation from configuration files
    - User preference persistence via cookie mechanism
    - Interactive target selection and configuration display
    - Comprehensive policy deployment confirmation workflow
    - Error handling and graceful exit procedures

    FUNCTION RELATIONSHIPS:
    - main(): Primary entry point handling user interface and menu interactions
    - deploy_policy(): Called by main() to handle deployment workflow and validation
    - build_policy(): Called by deploy_policy() to perform actual policy construction
    
    CLEAR FUNCTIONAL SEPARATION:
    - main(): User interface layer - handles menus, user input, and confirmation dialogs
    - deploy_policy(): Business logic layer - manages credentials, validation, and orchestration
    - build_policy(): Technical implementation layer - performs actual PAN-OS API operations

    Args:
        **kwargs: Variable keyword arguments for command-line parameters.
            Currently reserved for future command-line interface implementation.
            When implemented, will support automated deployment scenarios.

    Returns:
        int: Application exit code:
            - 0: Successful execution or user-initiated graceful exit
            - 1: Critical error preventing application startup or execution
                 (missing configuration files, invalid menu options, etc.)

    Raises:
        FileNotFoundError: When menu configuration files cannot be loaded.
        json.JSONDecodeError: When cookie or configuration files contain invalid JSON.
        KeyboardInterrupt: When user interrupts the application during execution.

    Note:
        The function supports cookie-based persistence for username and last menu choice,
        improving user experience for repeated deployments. Command-line argument support
        is planned for CI/CD pipeline integration but not yet implemented.
    """
    global menu_options

    # Load menu options if not already loaded
    if menu_options is None:
        menu_options = load_menu_options()
        if menu_options is None:
            return 1  # Return error code instead of sys.exit()

    global default_choice
    # Set default choice, ensuring it's a valid key in menu_options
    default_choice = "LAB Firewall"  # Default choice
    if menu_options and default_choice not in menu_options:
        # If default choice is not in menu_options, use the first key
        default_choice = list(menu_options.keys())[0]
        console.print(f"[yellow]Warning:[/yellow] Default choice 'LAB Firewall' not found in menu options. Using '{default_choice}' instead.")

    # Load last menu choice from cookie file if it exists
    if settings.USE_COOKIE:
        try:
            with open(settings.COOKIE_FILENAME, 'r') as f:
                cookie = json.load(f)
            if cookie.get('last_menu_choice') and cookie['last_menu_choice'] in menu_options:
                default_choice = cookie['last_menu_choice']
            elif cookie.get('last_menu_choice'):
                console.print(f"[yellow]Warning:[/yellow] Last menu choice '{cookie['last_menu_choice']}' not found in menu options. Using default choice '{default_choice}' instead.")
        except FileNotFoundError:
            pass

    # Check if any command line arguments are provided
    if len(sys.argv) == 1:
        display_menu()
        choice = get_user_choice()
        
        # Handle exit option
        if choice == 0:
            console.print("[bold yellow]Exiting program.[/bold yellow]")
            return 0
            
        selected_option = list(menu_options.keys())[choice - 1]

        # Set variables based on user choice
        arguments               = menu_options[selected_option]
        target_environment      = arguments["target_environment"]
        panos_address           = arguments["panos_address"]
        deployment_type         = arguments["deployment_type"]
        panorama_device_group   = arguments["panorama_device_group"] if "panorama_device_group" in arguments else None
        panorama_template       = arguments["panorama_template"]     if "panorama_template"     in arguments else None
        firewall_vsys           = arguments["firewall_vsys"]         if "firewall_vsys"         in arguments else None

        # Build the target information content
        target_info = []
        target_info.append(f"Target Environment:     [bold]{target_environment}[/bold]")
        target_info.append(f"PANOS Address:          [bold]{panos_address}[/bold]")
        target_info.append(f"Deployment Type:        [bold]{deployment_type}[/bold]")
        if deployment_type == "panorama":
            target_info.append(f"Panorama Device Group:  [bold]{panorama_device_group}[/bold]")
            target_info.append(f"Panorama Template:      [bold]{panorama_template}[/bold]")
        if deployment_type == "firewall":
            target_info.append(f"Firewall VSYS:          [bold]{firewall_vsys}[/bold]")

        # Create and display the panel with the target information
        target_panel = Panel.fit("\n".join(target_info), title=f"{' '.join(selected_option.split())}", border_style="blue")
        console.print("Selected the option:")
        console.print("")
        console.print(target_panel)
        console.print("")
        console.print(f"All policy rules will be created assuming the following zone names "
                      f"exist on the firewall (rename them in `settings.py` if required):\n\n"
                      f"Internal network:            [bold]{settings.ZONE_INSIDE}[/bold]\n"
                      f"External network (Internet): [bold]{settings.ZONE_OUTSIDE}[/bold]")
        console.print("")
        console.print(f'The script will deploy the policy version [bold]{settings.POLICY_VERSION}[/bold], dated [bold]{settings.POLICY_DATE}[/bold].\n'
              f'All existing policy rules and associated objects, such as address objects and groups, tags,\n'
              f'profiles, services, EDLs, custom signatures, data patterns etc., will be deleted and recreated\n'
              f'from the ground up as prescribed in the code in this repository.\n\n'
              f'The dynamic part of the security policy will be generated based on the business\n'
              f'requirements specified in the files as follows:\n\n'
              f'App categories: [bold]{settings.APP_CATEGORIES_REQUIREMENTS_FILENAME}[/bold]\n'
              f'URL categories: [bold]{settings.URL_CATEGORIES_REQUIREMENTS_FILENAME}[/bold]\n'
              f'\nThe static part of the policy will be generated based on the rules located in\n'
              f'the folder(s) as follows:\n\n'
              f'[bold]{settings.SECURITY_RULES_PRE_FOLDER}[/bold]')
        if settings.DELETE_CURRENT_DECRYPTION_POLICY:
            console.print(f'[bold]{settings.DECRYPTION_RULES_PRE_FOLDER}[/bold]\n'
                          f'[bold]{settings.DECRYPTION_RULES_POST_FOLDER}[/bold]\n')

        # Ask for confirmation with clear instructions and validation
        while True:
            choice = input(f"Enter 'YES' to Continue or 'NO' to Abort script execution: ")
            choice = choice.strip().upper()
            if choice == 'YES':
                # If we get here, the user confirmed with 'YES'
                # Call the deploy_policy function to handle the deployment
                return deploy_policy(
                    selected_option=selected_option,
                    arguments=arguments,
                    target_environment=target_environment,
                    panos_address=panos_address,
                    deployment_type=deployment_type,
                    panorama_device_group=panorama_device_group,
                    panorama_template=panorama_template,
                    firewall_vsys=firewall_vsys
                )
            elif choice == 'NO':
                console.print("[bold yellow]Operation aborted by user.[/bold yellow]")
                return 0
            else:
                console.print("[bold red]Invalid input.[/bold red] Please enter 'YES' to continue or 'NO' to abort.")
                continue

    else:
        # =================================================================================================================
        # COMMAND LINE INTERFACE (FUTURE IMPLEMENTATION)
        # =================================================================================================================
        
        # TODO: Implement command-line argument parsing for CI/CD integration
        # When implemented, this will support automated deployment scenarios without user interaction
        print("Command line arguments detected. Skipping menu...")
        print("Command line parameter handling is not implemented yet - use interactive option for now (run without any arguments).")


if __name__ == "__main__":
    # Only load menu options and execute interactive code when run as a script
    menu_options = load_menu_options()
    if menu_options is None:
        sys.exit(1)

    exit_code = main()
    if exit_code:
        sys.exit(exit_code)
