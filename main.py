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

# Global variables
menu_options = None
default_choice = None

if settings.RICH_TRACEBACKS:
    from rich.traceback import install
    install(show_locals=settings.RICH_TRACEBACKS_SHOW_VARS)
    if settings.VERBOSE_OUTPUT:
        console.print(f"[dim]Verbose mode has been enabled[/dim]")
        console.print(f"[dim]Rich traceback has been enabled[/dim]")

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
    Deploy policy to the specified target.

    Args:
        selected_option (str): The selected menu option
        arguments (dict): The arguments for the selected option
        target_environment (str): The target environment
        panos_address (str): The address of the PAN-OS device
        deployment_type (str): The type of deployment (panorama or firewall)
        panorama_device_group (str, optional): The Panorama device group. Defaults to None.
        panorama_template (str, optional): The Panorama template. Defaults to None.
        firewall_vsys (str, optional): The firewall VSYS. Defaults to None.

    Returns:
        int: 0 for success, 1 for error
    """
    console.print("\nProceeding with policy deployment...")

    # Obtain credentials
    # TODO: retrieve creds from ENV if executed with command line parameters as part of a CI/CD pipeline
    #
    # Read the default admin username from Settings
    default_admin_username = settings.DEFAULT_ADMIN_USERNAME
    # override it with username from Cookies file (if the feature is enabled)
    if settings.USE_COOKIE:
        try:
            with open(settings.COOKIE_FILENAME, 'r') as f:
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
            console.print("[bold red]Error:[/bold red] Username can only contain lowercase letters, numbers, underscores, dashes, and dots.")
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

    # Save provided username and last menu choice to the Cookie file (if the feature is enabled)
    if settings.USE_COOKIE:
        cookie = json.dumps({"admin_username": admin_username, "last_menu_choice": selected_option}, indent=4)
        with open(settings.COOKIE_FILENAME, 'w') as f:
            f.write(cookie)

    # Time the script execution (no interactive prompts expected after this point)
    start_time = time.time()

    # Create a PANOS device object as a target for the policy
    if deployment_type == 'panorama':
        panos_device = Panorama(hostname=panos_address, api_username=admin_username, api_password=admin_password)
    elif deployment_type == 'firewall':
        panos_device = Firewall(hostname=panos_address, api_username=admin_username, api_password=admin_password, vsys="shared")
    else:
        print(f"!!! Unknown deployment type ({deployment_type}). Aborting script execution...")
        return 1

    console.print('\nProceeding with policy provisioning to the specified device...')

    # Check if templates exist for APP and URL categories, and if not - create them from scratch
    # NOTE: This is not Panorama Templates !!!
    # We pull all categories from the actual device thus the device object needs to be passed on as the argument
    # we're also going to cross-reference the list of current categories them with requirements
    # and flag categories that arem not covered by the CSV spreadsheets with business requirements.
    # this is needed to track changes occasionally made by the vendor via dynamic content updates
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
    Main function for deploying policy versions. This function prompts the user to select deployment
    options, retrieves credentials, and performs configuration using specified options.
    It supports deployment to Panorama and standalone firewalls, including validation of category
    templates and building policies accordingly.

    Args:
        ``**kwargs``: Command-line arguments passed to the script for deployment configuration

    Returns:
        int: 0 for success, 1 for error
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

            # Obtain credentials
            # TODO: retrieve creds from ENV if executed with command line parameters as part of a CI/CD pipeline
            #
            # Read the default admin username from Settings
            default_admin_username = settings.DEFAULT_ADMIN_USERNAME
            # override it with username from Cookies file (if the feature is enabled)
            if settings.USE_COOKIE:
                try:
                    with open(settings.COOKIE_FILENAME, 'r') as f:
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
                    console.print("[bold red]Error:[/bold red] Username can only contain lowercase letters, numbers, underscores, dashes, and dots.")
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

            # Save provided username and last menu choice to the Cookie file (if the feature is enabled)
            if settings.USE_COOKIE:
                cookie = json.dumps({"admin_username": admin_username, "last_menu_choice": selected_option}, indent=4)
                with open(settings.COOKIE_FILENAME, 'w') as f:
                    f.write(cookie)

            # Time the script execution (no interactive prompts expected after this point)
            start_time = time.time()

            # Create a PANOS device object as a target for the policy
            if deployment_type == 'panorama':
                panos_device = Panorama(hostname=panos_address, api_username=admin_username, api_password=admin_password)
            elif deployment_type == 'firewall':
                panos_device = Firewall(hostname=panos_address, api_username=admin_username, api_password=admin_password, vsys="shared")
            else:
                print(f"!!! Unknown deployment type ({deployment_type}). Aborting script execution...")
                return 1

            console.print('\nProceeding with policy provisioning to the specified device...')

            # Check if templates exist for APP and URL categories, and if not - create them from scratch
            # NOTE: This is not Panorama Templates !!!
            # We pull all categories from the actual device thus the device object needs to be passed on as the argument
            # we're also going to cross-reference the list of current categories them with requirements
            # and flag categories that arem not covered by the CSV spreadsheets with business requirements.
            # this is needed to track changes occasionally made by the vendor via dynamic content updates
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
                    print(f"Correct the requirements and re-run the script. Aborting script execution...")
                    return 1
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

    else:
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
