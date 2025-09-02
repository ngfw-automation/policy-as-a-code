"""
Policy analyzer module.
Contains core analysis logic for determining application and URL verdicts.
"""
import sys
import os
import json
import re
from typing import Dict, List, Tuple, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from lib.rich_output import console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from testing.lib.auxiliary import NORMALIZED_BUILT_IN_APPS
import settings


def load_application_groups():
    """Load application groups from JSON file."""
    try:
        # Get the project root directory
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        app_groups_path = os.path.join(project_root, 'ngfw', 'objects', 'application groups', 'app_groups.json')
        
        with open(app_groups_path, 'r') as f:
            app_groups = json.load(f)
        
        # Extract the specific groups we need
        web_browsing = None
        web_browsing_risky = None
        
        for group in app_groups:
            if group['name'] == 'APG-web-browsing':
                web_browsing = group['value']
            elif group['name'] == 'APG-web-browsing-risky':
                web_browsing_risky = group['value']
        
        return web_browsing, web_browsing_risky
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load application groups from JSON: {str(e)}[/yellow]")
        # Fallback to hardcoded values
        return (['web-browsing', 'ssl', 'google-base', 'google-app-engine', 'soap', 'websocket'],
                ['web-browsing', 'ssl', 'google-base', 'google-app-engine', 'soap'])


# Load application groups from JSON
APP_GEN_WEB_BROWSING, APP_GEN_WEB_BROWSING_RISKY = load_application_groups()

# Application exceptions - apps that are explicitly allowed
APP_EXCEPTIONS = [
    'ntp-base', 'dns-base', 'oscp', 'windows-defender-atp-endpoint', 'office365-enterprise-access',
    'APP-darktrace-sensor-base', 'APP-darktrace-sensor-events', 'APP-darktrace-sensor-packetdata',
    'crowdstrike', 'prisma-cloud-compute-defender',
    'skype-probe', 'skype', 'ping', 'traceroute', 'paloalto-shared-services', 'paloalto-updates',
    'ms-delve', 'sway', 'ms-lync-base', 'ms-lync-audio', 'ms-lync-video', 'stun',
    'jamf', 'apple-push-notifications', 'windows-push-notifications', 'microsoft-intune', 'jfrog-artifactory',
    'sap', 'office365-enterprise-access', 'ms-update', 'google-update', 'java-update', 'paloalto-iot-security',
    'ms-product-activation', 'adobe-update', 'windows-push-notifications', 'apple-appstore', 'apple-update',
    'pagerduty', 'datadog', 'draw.io-base', 'nasuni', 'shodan', 'new-relic', 'google-cloud-storage-base',
    'bloomberg-professional', 'cust-greenhouse-s3', 'google-cloud-storage-base', 'google-cloud-storage-download',
    'calendly'
]

# Application container exceptions
APP_CONTAINER_EXCEPTIONS = [
    'zoom', 'ms-office365', 'boxnet', 'ms-onedrive', 'service-now', 'ms-onenote', 'docusign', 'ms-visual-studio-tfs'
]


def determine_app_verdict(app_name: str, app_container: str, app_category: str, 
                         app_group_dictionary: Dict[str, List[str]], 
                         managed_categories: List[str], 
                         non_managed_categories: List[str],
                         app_categories: List[Dict]) -> Tuple[str, str]:
    """
    Determine the verdict for an application based on policy rules.
    
    Args:
        app_name: Name of the application
        app_container: Application container name
        app_category: Application category
        app_group_dictionary: Dictionary mapping categories to application lists
        managed_categories: List of managed category names
        non_managed_categories: List of non-managed category names
        app_categories: List of category dictionaries with UserID mappings
        
    Returns:
        Tuple of (verdict, ad_group)
    """
    # First, check if app container or app itself is in the list of exceptions
    if app_name in APP_GEN_WEB_BROWSING and app_name in APP_GEN_WEB_BROWSING_RISKY:
        return 'The application is going to be allowed subject to URL filtering', 'varies'
    elif app_name in APP_GEN_WEB_BROWSING and app_name not in APP_GEN_WEB_BROWSING_RISKY:
        return 'The application is going to be allowed subject to URL filtering and provided that the risk is LOW', 'varies'
    elif app_container in APP_CONTAINER_EXCEPTIONS or app_name in APP_EXCEPTIONS:
        return "The application is going to be explicitly allowed by a dedicated policy rule", 'irrelevant'
    
    # Second, check if the category of the application is in the list of managed or non-managed ones
    elif app_category in app_group_dictionary:
        # Check if the application itself is in the respective application group
        if app_name in app_group_dictionary[app_category]:
            # Application is sanctioned, check if category is managed or non-managed
            if app_category in managed_categories:
                # Find the AD group corresponding to the category
                ad_group = 'unknown'
                for category in app_categories:
                    if category['Category'] == app_category:
                        ad_group = category.get("UserID", 'unknown')
                        break
                return 'The application is going to be allowed provided the user is in the respective AD group', ad_group
            elif app_category in non_managed_categories:
                return 'The application is going to be allowed provided the user is authenticated', 'known-user'
        else:
            return 'The application is going to be blocked as a non-sanctioned one', 'irrelevant'
    else:
        return 'The application is going to be blocked because it is in a blocked category and it is not in the list of exceptions', 'irrelevant'
    
    # Default case
    return 'unknown', 'unknown'


def determine_app_verdict_synthetic(
    app_name: str, 
    app_container: str, 
    app_category: str,
    ip_protocol: str,
    destination_port: int,
    panos_device,
    source_ip: str = None,
    destination_ip: str = "93.184.216.34",  # example.com fallback
    app_info: Dict = None
) -> Tuple[str, str, Dict]:
    """
    Determine application verdict using synthetic policy testing with actual traffic parameters.
    
    Args:
        app_name: Name of the application
        app_container: Application container name  
        app_category: Application category
        ip_protocol: IP protocol from traffic log ("tcp" or "udp")
        destination_port: Actual destination port from traffic log
        panos_device: PAN-OS device object for testing
        source_ip: Source IP for testing
        destination_ip: Destination IP for testing
        app_info: Application information from NORMALIZED_BUILT_IN_APPS
        
    Returns:
        Tuple of (verdict, ad_group, test_results)
    """
    
    # Validate inputs
    if not panos_device:
        return "Error: No firewall connection available", "unknown", {}
    
    if not source_ip:
        return "Error: Source IP not configured for testing", "unknown", {}
    
    # Convert protocol string to protocol number
    protocol_map = {"tcp": 6, "udp": 17}
    protocol = protocol_map.get(ip_protocol.lower(), 6)  # Default to TCP if unknown
    
    try:
        # Perform synthetic policy test using actual traffic parameters
        test_results = panos_device.test_security_policy_match(
            source=source_ip,
            destination=destination_ip,
            port=destination_port,  # Use actual port from traffic
            protocol=protocol,      # Use actual protocol from traffic
            application=app_name,
            from_zone=settings.ZONE_INSIDE,
            to_zone=settings.ZONE_OUTSIDE,
            show_all=False
        )
        
        # Analyze test results to determine verdict
        if test_results:
            rule = test_results[0]  # Get first matching rule
            action = rule.get('action', 'unknown').lower()
            rule_name = rule.get('name', 'unknown')
            rule_index = rule.get('index', 'unknown')
            
            # Determine verdict based on actual policy match
            if action == 'allow':
                # Analyze rule name to determine AD group requirements
                ad_group = _extract_ad_group_from_rule(rule_name, app_category)
                verdict = _generate_allow_verdict(rule_name, ad_group)
            elif action == 'deny':
                ad_group = 'irrelevant'
                verdict = f"The application is blocked by security rule '{rule_name}'"
            else:
                ad_group = 'unknown'
                verdict = f"Unknown action '{action}' from rule '{rule_name}'"
                
            return verdict, ad_group, {
                'rule_name': rule_name,
                'rule_index': rule_index,
                'action': action,
                'port_used': destination_port,
                'protocol_used': ip_protocol,
                'app_info': app_info
            }
        else:
            return "No matching security rule found", "unknown", {
                'port_used': destination_port,
                'protocol_used': ip_protocol,
                'app_info': app_info
            }
            
    except Exception as e:
        return f"Error during policy testing: {str(e)}", "unknown", {
            'error': str(e),
            'port_used': destination_port,
            'protocol_used': ip_protocol
        }


def _extract_ad_group_from_rule(rule_name: str, app_category: str) -> str:
    """Extract AD group from rule name patterns."""
    # Map rule naming patterns to AD groups
    if 'managed' in rule_name.lower():
        # Look up category-specific AD group from configuration
        # This would need app_categories passed as parameter or accessed globally
        return 'managed-user'  # Simplified for this example
    elif 'non-managed' in rule_name.lower() or 'authenticated' in rule_name.lower():
        return 'known-user'
    else:
        return 'irrelevant'


def _generate_allow_verdict(rule_name: str, ad_group: str) -> str:
    """Generate human-readable verdict for allow actions."""
    if ad_group == 'known-user':
        return "The application is allowed provided the user is authenticated"
    elif ad_group != 'irrelevant' and ad_group != 'unknown':
        return f"The application is allowed provided the user is in the AD group '{ad_group}'"
    else:
        return f"The application is allowed by security rule '{rule_name}'"


def _extract_port_number_from_defaults(default_ports):
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


def _extract_protocol_from_defaults(default_ports):
    """
    Extract protocol from the default ports string.
    
    Args:
        default_ports: String or list containing default port information
        
    Returns:
        str: "tcp" or "udp", defaults to "tcp"
    """
    if not default_ports:
        return "tcp"
    
    # Convert to string if it's a list
    if isinstance(default_ports, list):
        if not default_ports:  # Empty list
            return "tcp"
        ports_str = default_ports[0]
    else:
        ports_str = str(default_ports)
    
    # Check for UDP protocol indicator
    if "udp/" in ports_str.lower():
        return "udp"
    else:
        return "tcp"  # Default to TCP


def _extract_source_ip_from_traffic(traffic_data: List[Dict]) -> Optional[str]:
    """
    Extract source IP from traffic data if available.
    
    Args:
        traffic_data: List of traffic records
        
    Returns:
        Source IP address if found, None otherwise
    """
    for record in traffic_data:
        # Check common column names for source IP
        for ip_column in ['Source IP', 'Source', 'Src IP', 'SrcIP', 'source_ip']:
            if ip_column in record and record[ip_column]:
                ip_value = record[ip_column].strip()
                # Validate IP format
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_value):
                    return ip_value
    return None


def determine_source_ip_for_testing(traffic_data: List[Dict]) -> str:
    """
    Determine source IP for testing based on user preference.
    
    Args:
        traffic_data: List of traffic records
        
    Returns:
        Source IP address to use for testing
    """
    console.print("\n[bold blue]Source IP Configuration for Synthetic Testing[/bold blue]")
    console.print("The synthetic testing approach requires a source IP address for policy testing.")
    console.print("You have two options:")
    console.print("1. Use a static IP address for all tests")
    console.print("2. Extract source IP from the traffic report")
    
    while True:
        choice = input("\nChoose option (1 or 2): ").strip()
        if choice == "1":
            # Static IP option
            default_ip = "10.1.1.1"
            static_ip = input(f"Enter source IP address [{default_ip}]: ").strip() or default_ip
            
            # Validate IP format
            if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", static_ip):
                console.print(f"[green]✓[/green] Using static source IP: {static_ip}")
                return static_ip
            else:
                console.print("[red]Invalid IP address format. Please try again.[/red]")
                continue
                
        elif choice == "2":
            # Extract from report option
            console.print("[blue]Attempting to extract source IP from traffic report...[/blue]")
            extracted_ip = _extract_source_ip_from_traffic(traffic_data)
            
            if extracted_ip:
                console.print(f"[green]✓[/green] Found source IP in report: {extracted_ip}")
                return extracted_ip
            else:
                console.print("[yellow]⚠[/yellow] Could not find source IP in report. Using fallback.")
                fallback_ip = "10.1.1.1"
                console.print(f"[green]✓[/green] Using fallback source IP: {fallback_ip}")
                return fallback_ip
        else:
            console.print("[red]Invalid choice. Please enter 1 or 2.[/red]")


def determine_url_verdict(url_category: str,
                         managed_categories: List[str], 
                         non_managed_categories: List[str],
                         blocked_categories: List[str],
                         paused_categories: List[str],
                         url_categories: List[Dict]) -> Tuple[str, str]:
    """
    Determine the verdict for a URL category based on policy rules.
    
    Args:
        url_category: URL category name
        managed_categories: List of managed URL category names
        non_managed_categories: List of non-managed URL category names
        blocked_categories: List of blocked URL category names
        paused_categories: List of paused URL category names
        url_categories: List of category dictionaries with UserID mappings
        
    Returns:
        Tuple of (verdict, ad_group)
    """
    if url_category in managed_categories:
        # Find the AD group corresponding to the category
        ad_group = 'unknown'
        for category in url_categories:
            if category['Category'] == url_category:
                ad_group = category.get("UserID", 'unknown')
                break
        return 'The URL category is going to be allowed provided the user is in the respective AD group', ad_group
    elif url_category in non_managed_categories:
        return 'The URL category is going to be allowed provided the user is authenticated', 'known-user'
    elif url_category in blocked_categories:
        return 'The URL category is going to be blocked', 'irrelevant'
    elif url_category in paused_categories:
        return 'Access to the URL category is going to be paused (Continue action)', 'known-user'
    else:
        return 'The category is not a standard Palo Alto content/function-based category', 'irrelevant'


def analyze_application_traffic(traffic_data: List[Dict], 
                               app_group_dictionary: Dict[str, List[str]], 
                               managed_categories: List[str], 
                               non_managed_categories: List[str],
                               app_categories: List[Dict]) -> List[Dict]:
    """
    Analyze application traffic data and determine verdicts.
    
    Args:
        traffic_data: List of traffic records
        app_group_dictionary: Dictionary mapping categories to application lists
        managed_categories: List of managed category names
        non_managed_categories: List of non-managed category names
        app_categories: List of category dictionaries
        
    Returns:
        List of traffic records with verdicts added
    """
    console.print("[bold blue]Analyzing application traffic report...[/bold blue]")
    
    app_traffic_report_with_verdicts = []
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("Processing traffic records...", total=len(traffic_data))
        
        for line in traffic_data:
            app_name = line.get("Application", "")
            user_name = line.get("Source User", "")
            app_container = line.get("App Container", "")
            app_category = line.get("App Sub Category", "")
            app_bytes = line.get("Bytes", "")
            
            # Determine verdict for this application
            app_verdict, app_group = determine_app_verdict(
                app_name, app_container, app_category, 
                app_group_dictionary, managed_categories, non_managed_categories, app_categories
            )
            
            app_traffic_report_with_verdicts.append({
                "Source User": user_name,
                "Application": app_name,
                "Category": app_category,
                "Verdict": app_verdict,
                "AD Group": app_group,
                "Bytes": app_bytes
            })
            
            progress.advance(task)
    
    console.print(f"[green]Application traffic analysis completed ({len(app_traffic_report_with_verdicts)} records processed)[/green]")
    return app_traffic_report_with_verdicts


def analyze_application_traffic_synthetic(
    traffic_data: List[Dict], 
    panos_device,
    source_ip: str
) -> List[Dict]:
    """
    Analyze application traffic using synthetic policy testing with actual traffic parameters.
    
    Args:
        traffic_data: List of traffic records
        panos_device: PAN-OS device object for testing
        source_ip: Source IP address to use for testing
        
    Returns:
        List of traffic records with verdicts added
    """
    console.print("[bold blue]Analyzing application traffic with synthetic tests...[/bold blue]")
    
    app_traffic_report_with_verdicts = []
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Testing applications against policy...", total=len(traffic_data))
        
        for line in traffic_data:
            app_name = line.get("Application", "")
            user_name = line.get("Source User", "")
            app_container = line.get("App Container", "")
            app_category = line.get("App Sub Category", "")
            app_bytes = line.get("Bytes", "")
            
            # Get application info
            app_info = NORMALIZED_BUILT_IN_APPS.get(app_name, {})
            
            # Extract protocol and port from traffic data or fallback to application defaults
            ip_protocol = line.get("IP Protocol")
            destination_port_str = line.get("Destination Port")
            
            if ip_protocol and destination_port_str:
                # Use actual traffic data
                ip_protocol = ip_protocol.lower()
                try:
                    destination_port = int(destination_port_str)
                except (ValueError, TypeError):
                    destination_port = 443  # Fallback to HTTPS port
            else:
                # Fallback to application defaults
                console.print(f"[yellow]⚠[/yellow] Missing protocol/port for {app_name}, using application defaults")
                default_ports = app_info.get('default-ports')
                destination_port = _extract_port_number_from_defaults(default_ports)
                ip_protocol = _extract_protocol_from_defaults(default_ports)
            
            # Perform synthetic test using actual traffic parameters
            app_verdict, app_group, test_results = determine_app_verdict_synthetic(
                app_name, app_container, app_category, 
                ip_protocol, destination_port,  # Use actual traffic parameters
                panos_device, source_ip, app_info=app_info
            )
            
            app_traffic_report_with_verdicts.append({
                "Source User": user_name,
                "Application": app_name,
                "Category": app_category,
                "IP Protocol": ip_protocol,
                "Destination Port": destination_port,
                "Verdict": app_verdict,
                "AD Group": app_group,
                "Bytes": app_bytes,
                "Rule Name": test_results.get('rule_name', 'N/A'),
                "Rule Index": test_results.get('rule_index', 'N/A'),
                "Action": test_results.get('action', 'N/A')
            })
            
            progress.advance(task)
    
    console.print(f"[green]Application traffic analysis completed ({len(app_traffic_report_with_verdicts)} records processed)[/green]")
    return app_traffic_report_with_verdicts


def analyze_url_traffic(url_data: List[Dict],
                       managed_categories: List[str], 
                       non_managed_categories: List[str],
                       blocked_categories: List[str],
                       paused_categories: List[str],
                       url_categories: List[Dict]) -> List[Dict]:
    """
    Analyze URL traffic data and determine verdicts.
    
    Args:
        url_data: List of URL records
        managed_categories: List of managed URL category names
        non_managed_categories: List of non-managed URL category names
        blocked_categories: List of blocked URL category names
        paused_categories: List of paused URL category names
        url_categories: List of category dictionaries
        
    Returns:
        List of URL records with verdicts added
    """
    console.print("[bold blue]Analyzing URL traffic report...[/bold blue]")
    
    url_traffic_report_with_verdicts = []
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("Processing URL records...", total=len(url_data))
        
        for line in url_data:
            user_name = line.get("Source User", "")
            url_category = line.get("Category", "")
            url_count = line.get("Count", "")
            
            # Determine verdict for this URL category
            url_verdict, url_group = determine_url_verdict(
                url_category, managed_categories, non_managed_categories,
                blocked_categories, paused_categories, url_categories
            )
            
            url_traffic_report_with_verdicts.append({
                "Source User": user_name,
                "Category": url_category,
                "Verdict": url_verdict,
                "AD Group": url_group,
                "Count": url_count
            })
            
            progress.advance(task)
    
    console.print(f"[green]URL traffic analysis completed ({len(url_traffic_report_with_verdicts)} records processed)[/green]")
    return url_traffic_report_with_verdicts


def categorize_url_categories(url_categories: List[Dict]) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Categorize URL categories based on their actions.
    
    Args:
        url_categories: List of URL category dictionaries
        
    Returns:
        Tuple of (managed, non_managed, blocked, paused) category lists
    """
    managed_categories = []
    non_managed_categories = []
    blocked_categories = []
    paused_categories = []
    
    for category in url_categories:
        action = category.get('Action', '')
        category_name = category.get('Category', '')
        
        if action == settings.URL_ACTION_MANAGE:
            managed_categories.append(category_name)
        elif action == settings.url_action_alert:
            non_managed_categories.append(category_name)
        elif action == settings.URL_ACTION_DENY:
            blocked_categories.append(category_name)
        elif action == settings.URL_ACTION_CONTINUE:
            paused_categories.append(category_name)
    
    return managed_categories, non_managed_categories, blocked_categories, paused_categories


def get_analysis_summary(app_results: List[Dict], url_results: List[Dict]) -> Dict[str, int]:
    """
    Generate summary statistics for the analysis results.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
        
    Returns:
        Dictionary containing summary statistics
    """
    summary = {
        'total_app_records': len(app_results),
        'total_url_records': len(url_results),
        'app_allowed': 0,
        'app_blocked': 0,
        'app_conditional': 0,
        'url_allowed': 0,
        'url_blocked': 0,
        'url_conditional': 0
    }
    
    # Analyze application verdicts
    for record in app_results:
        verdict = record.get('Verdict', '').lower()
        if 'blocked' in verdict:
            summary['app_blocked'] += 1
        elif 'allowed' in verdict and ('provided' in verdict or 'subject' in verdict):
            summary['app_conditional'] += 1
        elif 'allowed' in verdict:
            summary['app_allowed'] += 1
    
    # Analyze URL verdicts
    for record in url_results:
        verdict = record.get('Verdict', '').lower()
        if 'blocked' in verdict:
            summary['url_blocked'] += 1
        elif 'allowed' in verdict and 'provided' in verdict:
            summary['url_conditional'] += 1
        elif 'allowed' in verdict:
            summary['url_allowed'] += 1
    
    return summary


def display_analysis_summary(summary: Dict[str, int]) -> None:
    """
    Display analysis summary in a formatted way.
    
    Args:
        summary: Dictionary containing summary statistics
    """
    console.print("[bold blue]Analysis Summary:[/bold blue]")
    console.print(f"[blue]Application Records:[/blue] {summary['total_app_records']}")
    console.print(f"  [green]Allowed:[/green] {summary['app_allowed']}")
    console.print(f"  [yellow]Conditional:[/yellow] {summary['app_conditional']}")
    console.print(f"  [red]Blocked:[/red] {summary['app_blocked']}")
    console.print(f"[blue]URL Records:[/blue] {summary['total_url_records']}")
    console.print(f"  [green]Allowed:[/green] {summary['url_allowed']}")
    console.print(f"  [yellow]Conditional:[/yellow] {summary['url_conditional']}")
    console.print(f"  [red]Blocked:[/red] {summary['url_blocked']}")