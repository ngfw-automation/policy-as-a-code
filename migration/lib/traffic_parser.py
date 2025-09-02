"""
Traffic report parsing module.
Handles parsing of CSV traffic reports for applications and URLs.
"""
import csv
import sys
import os
from typing import List, Dict, Optional
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from lib.rich_output import console
from lib.auxiliary_functions import parse_metadata_from_csv


def parse_traffic_report(filename: str) -> Optional[List[Dict]]:
    """
    Parse application traffic report from CSV file.
    
    Args:
        filename: Path to the traffic report CSV file
        
    Returns:
        List of dictionaries containing traffic data, or None if parsing fails
    """
    try:
        console.print(f"[blue]Reading traffic report: {filename}[/blue]")
        traffic_data = parse_metadata_from_csv('TRAFFIC REPORT (Applications)', filename)
        
        if traffic_data is None:
            console.print(f"[red]Failed to parse traffic report: {filename}[/red]")
            return None
            
        console.print(f"[green]Successfully parsed {len(traffic_data)} traffic records[/green]")
        return traffic_data
        
    except FileNotFoundError:
        console.print(f"[red]Traffic report file not found: {filename}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error parsing traffic report: {str(e)}[/red]")
        return None


def parse_url_report(filename: str) -> Optional[List[Dict]]:
    """
    Parse URL traffic report from CSV file.
    
    Args:
        filename: Path to the URL report CSV file
        
    Returns:
        List of dictionaries containing URL data, or None if parsing fails
    """
    try:
        console.print(f"[blue]Reading URL report: {filename}[/blue]")
        url_data = parse_metadata_from_csv('TRAFFIC REPORT (URLs)', filename)
        
        if url_data is None:
            console.print(f"[red]Failed to parse URL report: {filename}[/red]")
            return None
            
        console.print(f"[green]Successfully parsed {len(url_data)} URL records[/green]")
        return url_data
        
    except FileNotFoundError:
        console.print(f"[red]URL report file not found: {filename}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error parsing URL report: {str(e)}[/red]")
        return None


def validate_report_format(report_data: List[Dict], report_type: str) -> bool:
    """
    Validate the format of parsed report data.
    
    Args:
        report_data: List of dictionaries containing report data
        report_type: Type of report ('traffic' or 'url')
        
    Returns:
        True if format is valid, False otherwise
    """
    if not report_data:
        console.print(f"[red]{report_type} report is empty[/red]")
        return False
    
    required_fields = {
        'traffic': ['Source User', 'Application', 'App Sub Category', 'Bytes'],
        'url': ['Source User', 'URL', 'Category', 'Count']
    }
    
    if report_type not in required_fields:
        console.print(f"[red]Unknown report type: {report_type}[/red]")
        return False
    
    expected_fields = required_fields[report_type]
    sample_record = report_data[0]
    
    missing_fields = [field for field in expected_fields if field not in sample_record]
    if missing_fields:
        console.print(f"[red]Missing required fields in {report_type} report: {missing_fields}[/red]")
        return False
    
    console.print(f"[green]{report_type.capitalize()} report format validation passed[/green]")
    return True


def load_and_validate_reports(traffic_filename: str, url_filename: str) -> tuple[Optional[List[Dict]], Optional[List[Dict]]]:
    """
    Load and validate both traffic and URL reports.
    
    Args:
        traffic_filename: Path to traffic report CSV file
        url_filename: Path to URL report CSV file
        
    Returns:
        Tuple of (traffic_data, url_data) or (None, None) if validation fails
    """
    console.print("[bold blue]Loading traffic reports...[/bold blue]")
    
    # Parse both reports
    traffic_data = parse_traffic_report(traffic_filename)
    url_data = parse_url_report(url_filename)
    
    # Check if both files were parsed successfully
    if traffic_data is None or url_data is None:
        console.print(f"[red]Both files with traffic reports ({traffic_filename}, {url_filename}) must exist and be valid for the script to execute successfully.[/red]")
        console.print("[yellow]Generate them on a PAN-OS device, save under the file names specified above, and re-run the script.[/yellow]")
        return None, None
    
    # Validate report formats
    if not validate_report_format(traffic_data, 'traffic') or not validate_report_format(url_data, 'url'):
        return None, None
    
    console.print("[green]All traffic reports loaded and validated successfully[/green]")
    return traffic_data, url_data


def get_default_filenames() -> tuple[str, str]:
    """
    Get default filenames for traffic reports.
    
    Returns:
        Tuple of (traffic_filename, url_filename)
    """
    return "traffic_report_app.csv", "traffic_report_url.csv"


def check_report_files_exist(traffic_filename: str, url_filename: str) -> bool:
    """
    Check if both report files exist.
    
    Args:
        traffic_filename: Path to traffic report file
        url_filename: Path to URL report file
        
    Returns:
        True if both files exist, False otherwise
    """
    traffic_exists = Path(traffic_filename).exists()
    url_exists = Path(url_filename).exists()
    
    if not traffic_exists:
        console.print(f"[red]Traffic report file not found: {traffic_filename}[/red]")
    if not url_exists:
        console.print(f"[red]URL report file not found: {url_filename}[/red]")
    
    return traffic_exists and url_exists