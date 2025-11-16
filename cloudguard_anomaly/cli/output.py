"""
CLI output utilities with color support.

Provides severity-based coloring and rich formatting for terminal output.
"""

import sys
from typing import Optional, List, Any
from enum import Enum

# Try to import rich for enhanced output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.tree import Tree
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Try to import colorama for cross-platform colors
try:
    from colorama import init as colorama_init, Fore, Style, Back
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class OutputLevel(Enum):
    """Output verbosity levels."""
    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3


class CliOutput:
    """CLI output manager with color and formatting support."""

    def __init__(self, verbose: int = OutputLevel.NORMAL.value, no_color: bool = False):
        """
        Initialize CLI output.

        Args:
            verbose: Verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug)
            no_color: Disable colored output
        """
        self.verbose_level = OutputLevel(verbose)
        self.no_color = no_color
        self.console = Console() if RICH_AVAILABLE and not no_color else None

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level."""
        if self.no_color or not COLORAMA_AVAILABLE:
            return ""

        severity_lower = severity.lower()
        if severity_lower == "critical":
            return Fore.RED + Style.BRIGHT
        elif severity_lower == "high":
            return Fore.RED
        elif severity_lower == "medium":
            return Fore.YELLOW
        elif severity_lower == "low":
            return Fore.BLUE
        elif severity_lower == "info":
            return Fore.CYAN
        else:
            return ""

    def _reset_color(self) -> str:
        """Get color reset code."""
        if self.no_color or not COLORAMA_AVAILABLE:
            return ""
        return Style.RESET_ALL

    def success(self, message: str):
        """Print success message in green."""
        if self.verbose_level.value < OutputLevel.NORMAL.value:
            return

        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"✅ {message}", style="bold green")
        elif COLORAMA_AVAILABLE and not self.no_color:
            print(f"{Fore.GREEN}{Style.BRIGHT}✅ {message}{Style.RESET_ALL}")
        else:
            print(f"✓ {message}")

    def error(self, message: str):
        """Print error message in red."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"❌ {message}", style="bold red")
        elif COLORAMA_AVAILABLE and not self.no_color:
            print(f"{Fore.RED}{Style.BRIGHT}❌ {message}{Style.RESET_ALL}", file=sys.stderr)
        else:
            print(f"✗ {message}", file=sys.stderr)

    def warning(self, message: str):
        """Print warning message in yellow."""
        if self.verbose_level.value < OutputLevel.NORMAL.value:
            return

        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"⚠️  {message}", style="bold yellow")
        elif COLORAMA_AVAILABLE and not self.no_color:
            print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  {message}{Style.RESET_ALL}")
        else:
            print(f"! {message}")

    def info(self, message: str):
        """Print info message."""
        if self.verbose_level.value < OutputLevel.NORMAL.value:
            return

        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"ℹ️  {message}", style="cyan")
        elif COLORAMA_AVAILABLE and not self.no_color:
            print(f"{Fore.CYAN}ℹ️  {message}{Style.RESET_ALL}")
        else:
            print(f"i {message}")

    def debug(self, message: str):
        """Print debug message."""
        if self.verbose_level.value < OutputLevel.DEBUG.value:
            return

        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"🐛 {message}", style="dim")
        else:
            print(f"DEBUG: {message}")

    def severity(self, severity: str, message: str):
        """Print message with severity-based coloring."""
        color = self._get_severity_color(severity)
        reset = self._reset_color()

        # Icons for each severity
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️"
        }
        icon = icons.get(severity.lower(), "")

        formatted = f"{color}{icon} {severity.upper()}: {message}{reset}"
        print(formatted)

    def finding(self, finding: Any):
        """Print a security finding with formatting."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            # Rich formatted output
            severity_styles = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "cyan"
            }
            style = severity_styles.get(finding.severity.value.lower(), "")

            panel = Panel(
                f"[bold]{finding.title}[/bold]\n\n{finding.description}",
                title=f"[{style}]{finding.severity.value.upper()}[/{style}]",
                subtitle=f"Resource: {finding.resource.id}",
                border_style=style
            )
            self.console.print(panel)
        else:
            # Plain text output with colors
            self.severity(finding.severity.value, finding.title)
            print(f"  Resource: {finding.resource.id}")
            print(f"  {finding.description}")
            print()

    def table(self, title: str, columns: List[str], rows: List[List[str]]):
        """Print a formatted table."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            table = Table(title=title, show_header=True, header_style="bold magenta")
            for col in columns:
                table.add_column(col)
            for row in rows:
                table.add_row(*row)
            self.console.print(table)
        else:
            # Simple ASCII table
            print(f"\n{title}")
            print("=" * len(title))
            print(" | ".join(columns))
            print("-" * (len(" | ".join(columns))))
            for row in rows:
                print(" | ".join(row))
            print()

    def summary_stats(self, stats: dict):
        """Print summary statistics."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            table = Table(title="Scan Summary", show_header=False, box=None)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="bold white")

            for key, value in stats.items():
                table.add_row(key, str(value))

            self.console.print(table)
        else:
            print("\n📊 Scan Summary")
            print("=" * 40)
            for key, value in stats.items():
                print(f"{key}: {value}")
            print()

    def progress(self, description: str):
        """Create a progress context manager."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            return self.console.status(description)
        else:
            return _DummyProgress(description)

    def markdown(self, md_text: str):
        """Render markdown text."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            md = Markdown(md_text)
            self.console.print(md)
        else:
            print(md_text)

    def rule(self, title: str = ""):
        """Print a horizontal rule."""
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.rule(title)
        else:
            if title:
                print(f"\n{'=' * 10} {title} {'=' * 10}\n")
            else:
                print("=" * 80)


class _DummyProgress:
    """Dummy progress context manager for when rich is not available."""

    def __init__(self, description: str):
        self.description = description

    def __enter__(self):
        print(f"{self.description}...")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            print("Done.")
        return False


# Global CLI output instance
_output: Optional[CliOutput] = None


def get_output(verbose: int = OutputLevel.NORMAL.value, no_color: bool = False) -> CliOutput:
    """Get global CLI output instance."""
    global _output
    if _output is None:
        _output = CliOutput(verbose=verbose, no_color=no_color)
    return _output


def set_output(output: CliOutput):
    """Set global CLI output instance."""
    global _output
    _output = output
