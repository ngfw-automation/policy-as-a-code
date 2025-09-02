"""
Report generator module.
Handles generation and export of analysis results to CSV files.
"""
import csv
import sys
import os
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from lib.rich_output import console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel


def get_default_output_filenames() -> tuple[str, str]:
    """
    Get default output filenames for analysis results.
    
    Returns:
        Tuple of (app_output_filename, url_output_filename)
    """
    return "traffic_report_app_with_verdicts.csv", "traffic_report_url_with_verdicts.csv"


def save_app_analysis_results(results: List[Dict], filename: str) -> bool:
    """
    Save application analysis results to CSV file.
    
    Args:
        results: List of application analysis results
        filename: Output CSV filename
        
    Returns:
        True if successful, False otherwise
    """
    try:
        console.print(f"[blue]Saving application analysis results to '{filename}'...[/blue]")
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Writing CSV file...", total=len(results) + 1)
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(["Source User", "Application", "Category", "Verdict", "AD Group", "Bytes"])
                progress.advance(task)
                
                # Write data rows
                for record in results:
                    writer.writerow([
                        record.get("Source User", ""),
                        record.get("Application", ""),
                        record.get("Category", ""),
                        record.get("Verdict", ""),
                        record.get("AD Group", ""),
                        record.get("Bytes", "")
                    ])
                    progress.advance(task)
        
        console.print(f"[green]✓ Application analysis results saved successfully ({len(results)} records)[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]Error saving application analysis results: {str(e)}[/red]")
        return False


def save_url_analysis_results(results: List[Dict], filename: str) -> bool:
    """
    Save URL analysis results to CSV file.
    
    Args:
        results: List of URL analysis results
        filename: Output CSV filename
        
    Returns:
        True if successful, False otherwise
    """
    try:
        console.print(f"[blue]Saving URL analysis results to '{filename}'...[/blue]")
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Writing CSV file...", total=len(results) + 1)
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(["Source User", "Category", "Verdict", "AD Group", "Count"])
                progress.advance(task)
                
                # Write data rows
                for record in results:
                    writer.writerow([
                        record.get("Source User", ""),
                        record.get("Category", ""),
                        record.get("Verdict", ""),
                        record.get("AD Group", ""),
                        record.get("Count", "")
                    ])
                    progress.advance(task)
        
        console.print(f"[green]✓ URL analysis results saved successfully ({len(results)} records)[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]Error saving URL analysis results: {str(e)}[/red]")
        return False


def save_analysis_results(app_results: List[Dict], url_results: List[Dict], 
                         app_filename: Optional[str] = None, 
                         url_filename: Optional[str] = None) -> tuple[bool, bool]:
    """
    Save both application and URL analysis results.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
        app_filename: Optional custom filename for app results
        url_filename: Optional custom filename for URL results
        
    Returns:
        Tuple of (app_success, url_success)
    """
    if app_filename is None or url_filename is None:
        default_app, default_url = get_default_output_filenames()
        app_filename = app_filename or default_app
        url_filename = url_filename or default_url
    
    console.print("[bold blue]Saving analysis results...[/bold blue]")
    
    app_success = save_app_analysis_results(app_results, app_filename)
    url_success = save_url_analysis_results(url_results, url_filename)
    
    if app_success and url_success:
        console.print("[green]All analysis results saved successfully[/green]")
    elif app_success:
        console.print("[yellow]Application results saved, but URL results failed[/yellow]")
    elif url_success:
        console.print("[yellow]URL results saved, but application results failed[/yellow]")
    else:
        console.print("[red]Failed to save analysis results[/red]")
    
    return app_success, url_success


def display_results_preview(app_results: List[Dict], url_results: List[Dict], 
                           max_rows: int = 10) -> None:
    """
    Display a preview of analysis results in formatted tables.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
        max_rows: Maximum number of rows to display in preview
    """
    console.print("[bold blue]Analysis Results Preview[/bold blue]")
    
    # Application results preview
    if app_results:
        app_table = Table(title="Application Analysis Results (First 10 records)")
        app_table.add_column("User", style="cyan", no_wrap=True)
        app_table.add_column("Application", style="magenta")
        app_table.add_column("Category", style="green")
        app_table.add_column("Verdict", style="yellow")
        app_table.add_column("AD Group", style="blue")
        app_table.add_column("Bytes", style="red", justify="right")
        
        for i, record in enumerate(app_results[:max_rows]):
            verdict = record.get("Verdict", "")
            # Truncate long verdicts for display
            if len(verdict) > 50:
                verdict = verdict[:47] + "..."
            
            app_table.add_row(
                record.get("Source User", "")[:20],
                record.get("Application", "")[:20],
                record.get("Category", "")[:15],
                verdict,
                record.get("AD Group", "")[:15],
                str(record.get("Bytes", ""))
            )
        
        console.print(app_table)
        
        if len(app_results) > max_rows:
            console.print(f"[dim]... and {len(app_results) - max_rows} more application records[/dim]")
    
    console.print("")
    
    # URL results preview
    if url_results:
        url_table = Table(title="URL Analysis Results (First 10 records)")
        url_table.add_column("User", style="cyan", no_wrap=True)
        url_table.add_column("Category", style="green")
        url_table.add_column("Verdict", style="yellow")
        url_table.add_column("AD Group", style="blue")
        url_table.add_column("Count", style="red", justify="right")
        
        for i, record in enumerate(url_results[:max_rows]):
            verdict = record.get("Verdict", "")
            # Truncate long verdicts for display
            if len(verdict) > 50:
                verdict = verdict[:47] + "..."
            
            url_table.add_row(
                record.get("Source User", "")[:20],
                record.get("Category", "")[:20],
                verdict,
                record.get("AD Group", "")[:15],
                str(record.get("Count", ""))
            )
        
        console.print(url_table)
        
        if len(url_results) > max_rows:
            console.print(f"[dim]... and {len(url_results) - max_rows} more URL records[/dim]")


def generate_summary_report(app_results: List[Dict], url_results: List[Dict]) -> str:
    """
    Generate a text summary report of the analysis.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
        
    Returns:
        String containing the summary report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Count verdicts
    app_verdicts = {}
    url_verdicts = {}
    
    for record in app_results:
        verdict = record.get("Verdict", "Unknown")
        app_verdicts[verdict] = app_verdicts.get(verdict, 0) + 1
    
    for record in url_results:
        verdict = record.get("Verdict", "Unknown")
        url_verdicts[verdict] = url_verdicts.get(verdict, 0) + 1
    
    # Generate report
    report = f"""
Traffic Log Analysis Summary Report
Generated: {timestamp}

OVERVIEW
========
Total Application Records: {len(app_results)}
Total URL Records: {len(url_results)}

APPLICATION ANALYSIS RESULTS
============================
"""
    
    for verdict, count in sorted(app_verdicts.items()):
        percentage = (count / len(app_results) * 100) if app_results else 0
        report += f"{verdict}: {count} ({percentage:.1f}%)\n"
    
    report += f"""
URL ANALYSIS RESULTS
====================
"""
    
    for verdict, count in sorted(url_verdicts.items()):
        percentage = (count / len(url_results) * 100) if url_results else 0
        report += f"{verdict}: {count} ({percentage:.1f}%)\n"
    
    return report


def save_summary_report(app_results: List[Dict], url_results: List[Dict], 
                       filename: str = "traffic_analysis_summary.txt") -> bool:
    """
    Save a summary report to a text file.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
        filename: Output filename for the summary report
        
    Returns:
        True if successful, False otherwise
    """
    try:
        report = generate_summary_report(app_results, url_results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        console.print(f"[green]✓ Summary report saved to '{filename}'[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]Error saving summary report: {str(e)}[/red]")
        return False


def display_file_locations(app_filename: str, url_filename: str, 
                          summary_filename: Optional[str] = None) -> None:
    """
    Display the locations of generated files in a formatted panel.
    
    Args:
        app_filename: Application results filename
        url_filename: URL results filename
        summary_filename: Optional summary report filename
    """
    current_dir = Path.cwd()
    
    file_info = f"""[green]✓[/green] Application Results: {current_dir / app_filename}
[green]✓[/green] URL Results: {current_dir / url_filename}"""
    
    if summary_filename:
        file_info += f"\n[green]✓[/green] Summary Report: {current_dir / summary_filename}"
    
    panel = Panel(
        file_info,
        title="[bold blue]Generated Files[/bold blue]",
        border_style="blue"
    )
    
    console.print(panel)


def export_results_interactive(app_results: List[Dict], url_results: List[Dict]) -> None:
    """
    Interactive function to export analysis results with user options.
    
    Args:
        app_results: List of application analysis results
        url_results: List of URL analysis results
    """
    console.print("[bold blue]Export Analysis Results[/bold blue]")
    
    # Get filenames from user
    default_app, default_url = get_default_output_filenames()
    
    app_filename = input(f"Application results filename [{default_app}]: ").strip() or default_app
    url_filename = input(f"URL results filename [{default_url}]: ").strip() or default_url
    
    # Ask about summary report
    create_summary = input("Create summary report? [y/N]: ").strip().lower() in ['y', 'yes']
    summary_filename = None
    
    if create_summary:
        summary_filename = input("Summary report filename [traffic_analysis_summary.txt]: ").strip() or "traffic_analysis_summary.txt"
    
    # Save results
    app_success, url_success = save_analysis_results(app_results, url_results, app_filename, url_filename)
    
    if create_summary and (app_success or url_success):
        save_summary_report(app_results, url_results, summary_filename)
    
    # Display file locations
    if app_success or url_success:
        display_file_locations(app_filename, url_filename, summary_filename if create_summary else None)