"""
URL filtering test utilities for PAN-OS policy testing.

This module provides utilities for testing URL filtering policies in PAN-OS firewalls.
It includes functions for making HTTP/HTTPS requests to URLs, testing URL filtering
for a single user/group or for all groups, and exporting results to CSV and HTML formats.

Functions:
    _single_url_test: Test a single URL and return its status.
    test_url_filtering: Test URL filtering for the currently mapped user/group.
    _export_results: Export URL filtering test results to CSV and HTML files.
    test_url_filtering_for_all_groups: Test URL filtering for all user groups.
"""
from __future__ import annotations

import csv
import datetime as _dt
import os
import ssl
import sys
import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from bs4 import BeautifulSoup
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table, Text

from lib.rich_output import console
import settings
from lib.auxiliary_functions import parse_metadata_from_csv
from testing.lib.user_identity import map_user_to_ip_and_group  # cross-module call


def _single_url_test(url: str, protocol: str) -> tuple[str, str]:
    """
    Test a single URL and return its status.

    This function makes an HTTP or HTTPS request to the specified URL and analyzes
    the response to determine if the URL is allowed, blocked, or paused by the firewall's
    URL filtering policy.

    Args:
        url: The URL to test (without protocol)
        protocol: The protocol to use ('http' or 'https')

    Returns:
        tuple[str, str]: A tuple containing (status, detailed_result)
            status: One of 'Allowed', 'Paused', 'Blocked', or 'Unknown'
            detailed_result: A detailed description of the result, including status code and title
    """
    quoted = quote(f"{protocol.lower()}://{url}", safe=':"?&=\'<>/[]@')
    req = Request(quoted)
    result = status = "Unknown"

    try:
        if protocol.lower() == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urlopen(req, timeout=20, context=ctx)
        else:
            resp = urlopen(req, timeout=20)

        charset = resp.headers.get_content_charset() or "utf-8"
        body = resp.read().decode(charset)
        title = BeautifulSoup(body, "html.parser").title.string or "No title"
        status_code = resp.status

        if status_code == 200:
            if title == "Web Page Blocked":
                status = "Paused"
            else:
                status = "Allowed"
        result = f"{status_code} :: {title}"
        resp.close()

    except HTTPError as e:
        if e.code == 503:
            charset = e.headers.get_content_charset() or "utf-8"
            b = e.read().decode(charset)
            soup = BeautifulSoup(b, "html.parser")
            hdr = soup.find("h1").string.upper() if soup.find("h1") else "Service Unavailable"
            status = "Blocked"
            result = f"{e.code} :: {hdr}"
        else:
            status = "Blocked"
            result = f"{e.code} :: {e.reason}"
    except URLError as e:
        result = str(e.reason)
    except Exception as e:
        result = f"Error: {e}"

    return status, result


def test_url_filtering(panos_device=None):
    """
    Test URL filtering for the currently mapped user/group.

    This function reads a list of URLs from a CSV file and tests each URL to determine
    if it is allowed, blocked, or paused by the firewall's URL filtering policy for the
    currently mapped user/group. The results are displayed in a table and exported to
    CSV and HTML files.

    Args:
        panos_device: The PAN-OS device object (not used in this function but kept for
                     consistency with other test functions)

    Returns:
        None
    """
    console.print("[bold green]Testing URL filtering for currently mapped user/group…[/bold green]")

    urls = parse_metadata_from_csv("URLs", "../" + settings.TEST_URLS_FILENAME, suppress_output=True)
    if not urls:
        console.print(f"[bold red]No URLs in {settings.TEST_URLS_FILENAME}[/bold red]")
        input("Press Enter…"); return

    table = Table(title="URL Filtering Results")
    table.add_column("Proto", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Comment", style="yellow")
    table.add_column("Result")

    # Store test results in memory
    results = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as prog:
        task = prog.add_task("[cyan]Probing…", total=len(urls))
        for row in urls:
            proto, url, comment = row["Protocol"], row["URL"], row.get("Comment", "")
            status, detail = _single_url_test(url, proto)

            # Store the result
            result_entry = row.copy()
            result_entry["Status"] = status
            result_entry["Detail"] = detail
            results.append(result_entry)

            style = None
            if comment.lower() == "malicious":
                style = "on red"

            res_style = {"Allowed": "on green", "Blocked": "on red",
                         "Paused": "on yellow"}.get(status, None)
            table.add_row(
                Text(proto, style), Text(url, style), Text(comment, style),
                Text(status, style or res_style) if res_style else status)
            prog.update(task, advance=1)

    console.print(table)
    _export_results(results)
    input("Press Enter to continue…")


def _export_results(url_rows):
    """
    Export URL filtering test results to CSV and HTML files.

    This function takes the results of URL filtering tests and exports them to both
    CSV and HTML formats. The files are saved in the 'test-results' directory with
    timestamps in their filenames.

    Args:
        url_rows: A list of dictionaries containing URL test results, where each dictionary
                 has keys for 'Protocol', 'URL', 'Comment', 'Status', and 'Detail'

    Returns:
        None
    """
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = "test-results"; os.makedirs(out_dir, exist_ok=True)
    csv_f = f"{out_dir}/url_filter_{timestamp}.csv"
    html_f = f"{out_dir}/url_filter_{timestamp}.html"

    # CSV
    console.print(f"[bold green]CSV →[/bold green] {csv_f}")
    with open(csv_f, "w", newline="") as fp:
        w = csv.writer(fp); w.writerow(["Protocol", "URL", "Comment", "Result"])
        for r in url_rows:
            # Use stored status instead of re-testing
            status = r["Status"]
            w.writerow([r["Protocol"], r["URL"], r["Comment"], status])

    # HTML (compact)
    console.print(f"[bold green]HTML →[/bold green] {html_f}")
    with open(html_f, "w") as fp:
        fp.write(f"""<!doctype html><html><head><meta charset='utf-8'>
<title>URL filtering</title><style>
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:6px;text-align:left}}
th{{background:#f2f2f2}}
tr:nth-child(even){{background:#f9f9f9}}
.allowed{{background-color:#e6ffe6}}.blocked{{background-color:#ffe6e6}}
.paused{{background-color:#fffbe6}}</style></head><body>
<h1>URL Filtering Results</h1><p>{_dt.datetime.now():%Y-%m-%d %H:%M:%S}</p>
<table><tr><th>Proto</th><th>URL</th><th>Comment</th><th>Status</th></tr>
""")
        for r in url_rows:
            # Use stored status and detail instead of re-testing
            status = r["Status"]
            detail = r["Detail"]
            cls = status.lower()
            fp.write(f"<tr class='{cls}'><td>{r['Protocol']}</td>"
                     f"<td>{r['URL']}</td><td>{r['Comment']}</td>"
                     f"<td title='{detail}'>{status}</td></tr>")
        fp.write("</table></body></html>")


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
                    status, detailed_result = _single_url_test(url, protocol)
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
                    status, detailed_result = _single_url_test(url, protocol)
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
        .paused {{ background-color: #fffbe6; }} /* Light yellow */
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
