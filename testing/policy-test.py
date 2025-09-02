#!/usr/bin/env python3
"""
Entry-point that wires together the library modules.
Run this file exactly as you did before – everything else moved under lib/.
"""
import sys
import os
# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from lib.rich_output import console
from testing.lib     import auxiliary     as aux
from testing.lib     import user_identity as uid
from testing.lib     import url_testing   as urlt
from testing.lib     import dns_testing   as dnst
from testing.lib.application_testing import test_application, test_all_applications
import settings


if settings.RICH_TRACEBACKS:
    from rich.traceback import install
    install(show_locals=settings.RICH_TRACEBACKS_SHOW_VARS)
    if settings.VERBOSE_OUTPUT:
        console.print(f"[dim]Verbose mode has been enabled[/dim]")
        console.print(f"[dim]Rich traceback has been enabled[/dim]")

if settings.DEBUG_OUTPUT:
    import logging  # Python’s standard logging framework
    import http.client as http_client  # low-level HTTP protocol client
    import requests  # User-friendly HTTP library built on urllib3

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


def main() -> None:
    aux.display_banner()
    console.print("[green]Connecting to a firewall with deployed policy…[/green]")
    fw = aux.initialize_firewall()

    while True:
        choice = aux.display_menu()
        if choice == 1:
            uid.set_source_ip_for_testing()
        elif choice == 2:
            uid.set_domain_prefix(fw)
        elif choice == 3:
            uid.set_decryption_group(fw)
        elif choice == 4:
            uid.create_user_group_mapping(fw)
        elif choice == 5:
            urlt.test_url_filtering(fw)
        elif choice == 6:
            urlt.test_url_filtering_for_all_groups(fw)
        elif choice == 7:
            test_application(fw)
        elif choice == 8:
            test_all_applications(fw)
        elif choice == 9:
            dnst.test_dns_security(fw)
        elif choice == 10:
            console.print("[green]Bye![/green]"); break
        else:
            console.print("[red]Unknown option[/red]")

if __name__ == "__main__":
    main()
