"""
iKARMA Command Line Interface - Production Release

Provides command-line interface for kernel driver analysis.
"""

import argparse
import logging
import sys
import json
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress

from ikarma import __version__
from ikarma.core import Analyzer, AnalysisResult, HTMLReportGenerator


def setup_logging(verbose: bool = False, debug: bool = False):
    """Configure logging."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def print_banner():
    """Print iKARMA banner."""
    console = Console()
    banner_text = Text(r"""
   _ _  __    _    ____  __  __    _
  (_) |/ /   / \  |  _ \|  \/  |  / \     IOCTL Kernel
  | | ' /   / _ \ | |_) | |\/| | / _ \    Artifact Risk
  | | . \  / ___ \|  _ <| |  | |/ ___ \   Mapping & Analysis
  |_|_|\_\/_/   \_\_| \_\_|  |_/_/   \_\

  Production Release v2.0.1
""", style="bold cyan")
    console.print(Panel(banner_text, title="iKARMA", border_style="bold magenta"))


def print_summary(result: AnalysisResult, limit: int = 10):
    """Print analysis summary to console."""
    console = Console()

    # Analysis Summary Panel
    summary_table = Table.grid(expand=True)
    summary_table.add_column(style="cyan", width=25)
    summary_table.add_column()
    summary_table.add_row("Memory Image:", result.memory_image_path)
    summary_table.add_row("Image Size:", f"{result.memory_image_size / (1024*1024):.1f} MB")
    summary_table.add_row("Image Hash:", f"{result.memory_image_hash[:16]}...")
    summary_table.add_row("Analysis Duration:", f"{result.analysis_duration_seconds:.1f} seconds")
    summary_table.add_row("Volatility3 Available:", str(result.volatility_available))

    console.print(Panel(summary_table, title="[bold]ANALYSIS SUMMARY[/bold]", border_style="green"))

    # Driver Statistics Panel
    stats_table = Table.grid(expand=True)
    stats_table.add_column(style="cyan", width=30)
    stats_table.add_column()
    stats_table.add_row("Total Drivers Analyzed:", f"[bold white]{result.total_drivers_analyzed}[/bold white]")
    stats_table.add_row("High Risk Drivers:", f"[bold red]{result.high_risk_drivers}[/bold red]")
    stats_table.add_row("Drivers with Anti-Forensics:", f"[yellow]{result.drivers_with_antiforensic}[/yellow]")
    stats_table.add_row("Drivers with Hooks:", f"[red]{result.drivers_with_hooks}[/red]" if result.drivers_with_hooks > 0 else "[green]0[/green]")

    console.print(Panel(stats_table, title="[bold]DRIVER STATISTICS[/bold]", border_style="green"))

    # Cross-View Validation Panel
    if result.cross_view_result:
        cross_view_table = Table.grid(expand=True)
        cross_view_table.add_column(style="cyan", width=30)
        cross_view_table.add_column()
        cross_view_table.add_row("Hidden Drivers (DKOM):", f"[bold red]{result.hidden_drivers_detected}[/bold red]" if result.hidden_drivers_detected > 0 else "[green]0[/green]")
        cross_view_table.add_row("Remnant Drivers:", f"[yellow]{result.remnant_drivers_detected}[/yellow]")

        panel = Panel(cross_view_table, title="[bold]CROSS-VIEW VALIDATION (DKOM DETECTION)[/bold]", border_style="yellow")
        console.print(panel)

        if result.hidden_drivers_detected > 0:
            hidden_drivers_text = Text()
            for driver in result.cross_view_result.hidden_drivers:
                hidden_drivers_text.append(f"  - {driver.name} @ {hex(driver.base_address)}\n", style="bold yellow")
            console.print(Panel(hidden_drivers_text, title="[bold red]!!! CRITICAL: HIDDEN DRIVERS DETECTED !!![/bold red]", border_style="red"))


    # High-Risk Drivers Table
    high_risk = [d for d in result.drivers if d.risk_score >= 7.0]
    if high_risk:
        # Sort by risk score
        sorted_drivers = sorted(high_risk, key=lambda x: x.risk_score, reverse=True)

        # Apply limit
        displayed_drivers = sorted_drivers[:limit]

        table = Table(
            title=f"[bold red]HIGH RISK DRIVERS[/bold red] (Showing {len(displayed_drivers)} of {len(high_risk)})",
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="red"
        )
        table.add_column("#", style="bold yellow", width=4, justify="right")
        table.add_column("Driver Name", style="cyan", width=25, no_wrap=False)
        table.add_column("Risk", style="magenta", width=8, justify="center")
        table.add_column("Category", style="white", width=10)
        table.add_column("Base Address", style="green", width=14)
        table.add_column("Key Capabilities", style="yellow", width=30, no_wrap=False)
        table.add_column("Anti-Forensic Indicators", style="red", width=25, no_wrap=False)

        for i, driver in enumerate(displayed_drivers, 1):
            # Deduplicate and format capabilities (show unique types only)
            seen_caps = set()
            unique_caps = []
            for c in driver.capabilities:
                cap_name = c.capability_type.name.replace('_', ' ').title()
                if cap_name not in seen_caps:
                    seen_caps.add(cap_name)
                    unique_caps.append(cap_name)
                    if len(unique_caps) >= 3:
                        break

            cap_list = unique_caps
            total_unique_caps = len(set(c.capability_type.name for c in driver.capabilities))
            if total_unique_caps > 3:
                cap_list.append(f"(+{total_unique_caps-3} more types)")
            caps = '\n'.join(cap_list) if cap_list else "None"

            # Deduplicate and format anti-forensic indicators
            seen_afs = set()
            unique_afs = []
            for indicator in driver.anti_forensic_indicators:
                af_name = indicator.indicator_type.name.replace('_', ' ').title()
                if af_name not in seen_afs:
                    seen_afs.add(af_name)
                    unique_afs.append(af_name)
                    if len(unique_afs) >= 2:
                        break

            af_list = unique_afs
            total_unique_afs = len(set(i.indicator_type.name for i in driver.anti_forensic_indicators))
            if total_unique_afs > 2:
                af_list.append(f"(+{total_unique_afs-2} more types)")
            afs = '\n'.join(af_list) if af_list else "None"

            # Determine colors based on risk
            if driver.risk_score >= 8.5:
                risk_color = "bold red"
                category_color = "bold red"
            elif driver.risk_score >= 7.5:
                risk_color = "red"
                category_color = "red"
            else:
                risk_color = "yellow"
                category_color = "yellow"

            table.add_row(
                str(i),
                f"[{risk_color}]{driver.name}[/{risk_color}]",
                f"[{risk_color}]{driver.risk_score:.1f}[/{risk_color}]",
                f"[{category_color}]{driver.risk_category}[/{category_color}]",
                f"[dim]{hex(driver.base_address)}[/dim]",
                caps,
                afs
            )

        console.print(table)
        console.print()

        # Show truncation message if needed
        if len(high_risk) > limit:
            remaining = len(high_risk) - limit
            console.print(f"[dim yellow]  ... and {remaining} more high-risk drivers not shown. Use --limit {len(high_risk)} to see all.[/dim yellow]")
            console.print()

    # Known Vulnerable Drivers Table
    known_vulns = [d for d in result.drivers if d.is_known_vulnerable]
    if known_vulns:
        vuln_table = Table(
            title=f"[bold yellow]KNOWN VULNERABLE DRIVERS (LOLDrivers)[/bold yellow] - {len(known_vulns)} Found",
            show_header=True,
            header_style="bold white on dark_red",
            border_style="yellow"
        )
        vuln_table.add_column("#", style="bold yellow", width=4, justify="right")
        vuln_table.add_column("Driver Name", style="cyan", width=30, no_wrap=True)
        vuln_table.add_column("Risk Score", style="magenta", width=10, justify="center")
        vuln_table.add_column("CVEs", style="yellow", width=20, no_wrap=False)
        vuln_table.add_column("Description", style="white", width=50, no_wrap=False)

        for idx, driver in enumerate(known_vulns, 1):
            cves = '\n'.join(driver.known_cves[:3]) if driver.known_cves else "N/A"
            if driver.known_cves and len(driver.known_cves) > 3:
                cves += f"\n(+{len(driver.known_cves)-3} more)"

            description = driver.loldrivers_match.get('description', 'N/A') if driver.loldrivers_match else 'N/A'
            # Truncate description if too long
            if len(description) > 200:
                description = description[:197] + "..."

            vuln_table.add_row(
                str(idx),
                f"[bold red]!![/bold red] {driver.name}",
                f"[red]{driver.risk_score:.1f}[/red]",
                cves,
                description
            )
        console.print(vuln_table)
        console.print()

    # BYOVD / Dangerous API findings
    byovd_drivers = []
    for driver in result.drivers:
        api_caps = [c.description for c in driver.capabilities if "Dangerous API" in c.description]
        if api_caps:
            byovd_drivers.append((driver, api_caps))

    if byovd_drivers:
        console.print()
        panel_lines = [f"[bold cyan]BYOVD/Dangerous API Findings[/bold cyan] - {len(byovd_drivers)} driver(s)"]
        for driver, api_caps in byovd_drivers[:5]:
            api_list = ', '.join(api_caps[:3])
            if len(api_caps) > 3:
                api_list += f" (+{len(api_caps)-3} more)"
            panel_lines.append(f"  [yellow]- {driver.name}:[/yellow] {api_list}")
        if len(byovd_drivers) > 5:
            panel_lines.append(f"  [dim]{len(byovd_drivers)-5} more driver(s) with Dangerous API hits[/dim]")

        console.print(Panel("\n".join(panel_lines), title="[bold magenta]BYOVD[/bold magenta]", border_style="cyan"))
        console.print()
    else:
        console.print()
        console.print(Panel("No BYOVD / Dangerous API findings detected", title="[bold magenta]BYOVD[/bold magenta]", border_style="cyan"))
        console.print()

    # Hooked Drivers Section
    hooked_drivers = [d for d in result.drivers if any(mf.is_hooked for mf in d.major_function_info)]
    if hooked_drivers:
        console.print()
        hook_panel = Panel(
            f"[bold red]{len(hooked_drivers)} driver(s) with hooked MajorFunctions detected![/bold red]",
            title="[bold yellow]HOOK DETECTION[/bold yellow]",
            border_style="red"
        )
        console.print(hook_panel)

        for driver in hooked_drivers[:5]:  # Show first 5
            hooked_funcs = [mf for mf in driver.major_function_info if mf.is_hooked]
            func_names = ', '.join([mf._get_name() for mf in hooked_funcs[:3]])
            console.print(f"  [yellow]- {driver.name}:[/yellow] [red]{func_names}[/red]")
        console.print()

    if result.errors:
        error_text = Text()
        for error in result.errors:
            error_text.append(f"  !! {error}\n", style="red")
        console.print(Panel(error_text, title="[bold red]ERRORS[/bold red]", border_style="red"))
        console.print()


def cmd_analyze(args):
    """Run analysis command."""
    print_banner()

    memory_path = Path(args.memory)
    if not memory_path.exists():
        console = Console()
        console.print(f"[bold red]Error: Memory file not found: {memory_path}[/bold red]")
        return 1

    console = Console()
    console.print(f"Analyzing: {memory_path}")
    console.print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print()

    # Configure analysis
    config = {
        'apply_legitimacy_bonus': not args.no_legitimacy_bonus,
        'critical_threshold': args.critical_threshold,
        'high_threshold': args.high_threshold,
        'byovd_detailed': args.byovd_detailed,
        'dkom_deep': args.dkom_deep,
    }

    # Run analysis
    analyzer = Analyzer(str(memory_path), config)

    if not analyzer.initialize():
        console.print("[bold red]Error: Failed to initialize analyzer[/bold red]")
        return 1

    result = analyzer.analyze()

    # Print summary
    print_summary(result, limit=args.limit)

    # Auto-generate HTML report with timestamped filename
    try:
        # Generate filename: <dump_name>_<HHMM>_<DDMMYYYY>.html
        now = datetime.now()
        dump_name = memory_path.stem  # Get filename without extension
        timestamp = now.strftime('%H%M_%d%m%Y')
        html_filename = f"{dump_name}_{timestamp}.html"
        html_path = Path(html_filename)

        html_generator = HTMLReportGenerator(result)
        html_generator.generate(str(html_path))
        console.print(f"\n[green]HTML report auto-generated: {html_path}[/green]")
        console.print(f"[cyan]Open in browser to view the full interactive report[/cyan]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not generate HTML report: {e}[/yellow]")

    # Export JSON if requested
    if args.output:
        output_path = Path(args.output)
        analyzer.export_json(str(output_path))
        console.print(f"\n[green]Results exported to: {output_path}[/green]")

    # Export to stdout as JSON if requested
    if args.json:
        console.print(result.to_json(indent=2))
    
    # Cleanup
    analyzer.close()
    
    # Return exit code based on findings
    if result.hidden_drivers_detected > 0:
        return 2  # DKOM detected
    elif result.high_risk_drivers > 0:
        return 1  # High risk drivers found
    
    return 0


def cmd_list_loldrivers(args):
    """List known vulnerable drivers."""
    from ikarma.core import LOLDriversMatcher
    
    matcher = LOLDriversMatcher()
    matcher.load_database()
    
    stats = matcher.get_statistics()
    
    print("LOLDrivers Database Statistics")
    print("="*50)
    print(f"Total Entries: {stats['total_entries']}")
    print(f"Entries with MD5: {stats['entries_with_md5']}")
    print(f"Entries with SHA256: {stats['entries_with_sha256']}")
    print()
    print("Categories:")
    for cat, count in stats['categories'].items():
        print(f"  {cat}: {count}")
    
    if args.verbose:
        print()
        print("Known Vulnerable Drivers:")
        print("-"*50)
        for name in matcher.get_all_vulnerable_names():
            info = matcher.get_driver_info(name)
            if info:
                cves = info.get('cves', [])
                cve_str = ', '.join(cves) if cves else 'N/A'
                print(f"  {name}: {cve_str}")


def cmd_version(args):
    """Print version information."""
    print(f"iKARMA v{__version__}")
    print("Kernel Driver Analysis for Memory Forensics")
    print()
    
    # Check dependencies
    print("Dependencies:")
    
    try:
        import volatility3
        vol_ver = getattr(volatility3, '__version__', 'unknown')
        print(f"  Volatility3: {vol_ver}")
    except ImportError:
        print("  Volatility3: NOT INSTALLED")
    
    try:
        import capstone
        print(f"  Capstone: {capstone.CS_VERSION_MAJOR}.{capstone.CS_VERSION_MINOR}")
    except ImportError:
        print("  Capstone: NOT INSTALLED")
    
    try:
        import pefile
        print(f"  pefile: installed")
    except ImportError:
        print("  pefile: NOT INSTALLED")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='ikarma',
        description='iKARMA - Kernel Driver Analysis for Memory Forensics'
    )
    parser.add_argument('--version', action='store_true', help='Show version')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--debug', action='store_true', help='Debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze memory dump')
    analyze_parser.add_argument('memory', help='Path to memory dump file')
    analyze_parser.add_argument('-o', '--output', help='Output JSON file path')
    analyze_parser.add_argument('--json', action='store_true', help='Output JSON to stdout')
    analyze_parser.add_argument('--no-legitimacy-bonus', action='store_true',
                               help='Disable legitimacy bonus for signed drivers')
    analyze_parser.add_argument('--critical-threshold', type=float, default=8.0,
                               help='Critical risk threshold (default: 8.0)')
    analyze_parser.add_argument('--high-threshold', type=float, default=6.0,
                               help='High risk threshold (default: 6.0)')
    analyze_parser.add_argument('--limit', type=int, default=10,
                               help='Limit number of high risk drivers displayed (default: 10)')
    analyze_parser.add_argument('--byovd-detailed', action='store_true', default=False,
                               help='Include detailed BYOVD findings in capabilities')
    analyze_parser.add_argument('--dkom-deep', action='store_true', default=False,
                               help='Enable deeper DKOM scan heuristics where available')
    analyze_parser.set_defaults(func=cmd_analyze)
    
    # List LOLDrivers command
    lol_parser = subparsers.add_parser('loldrivers', help='List known vulnerable drivers')
    lol_parser.set_defaults(func=cmd_list_loldrivers)
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version and dependencies')
    version_parser.set_defaults(func=cmd_version)
    
    args = parser.parse_args()
    
    if args.version:
        cmd_version(args)
        return 0
    
    setup_logging(args.verbose, getattr(args, 'debug', False))
    
    if hasattr(args, 'func'):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
