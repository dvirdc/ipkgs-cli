"""Rich console helpers."""

from __future__ import annotations

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TransferSpeedColumn,
)


def make_console(no_color: bool = False) -> Console:
    return Console(no_color=no_color, highlight=False)


def make_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )


def print_success(console: Console, msg: str) -> None:
    console.print(f"[bold green]✓[/] {msg}")


def print_warning(console: Console, msg: str) -> None:
    console.print(f"[bold yellow]⚠[/] {msg}")


def print_error(console: Console, msg: str) -> None:
    Console(stderr=True, no_color=console.no_color, highlight=False).print(f"[bold red]✗[/] {msg}")
