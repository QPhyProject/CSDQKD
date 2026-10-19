"""
qsecure.ui - Terminal UI, Rich Styling, Responsive Layouts, and Visualization
=============================================================================
Provides dark laboratory aesthetics, responsive terminal dimension handling,
compact ASCII/Unicode charts, and consistent visual components.
"""

import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import ROUNDED, SIMPLE, SIMPLE_HEAVY
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Laboratory Color Theme
LAB_THEME = Theme(
    {
        "qkd": "bold cyan",
        "ckd": "bold dodger_blue1",
        "mkd": "bold magenta",
        "aes": "bold yellow",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "metric": "bold cyan",
        "dimmed": "dim white",
        "header": "bold white on grey15",
        "border": "grey35",
        "highlight": "bold bright_white",
        "pass": "bold black on green",
        "fail": "bold white on red",
        "warn_badge": "bold black on yellow",
        "theo_badge": "bold black on cyan",
        "meas_badge": "bold black on blue",
    }
)

def get_terminal_dimensions() -> Tuple[int, int]:
    """Return current terminal (width, height) respecting environment overrides."""
    try:
        env_col = os.environ.get("COLUMNS")
        env_lines = os.environ.get("LINES")
        size = shutil.get_terminal_size((80, 24))
        w = int(env_col) if env_col and env_col.isdigit() else size.columns
        h = int(env_lines) if env_lines and env_lines.isdigit() else size.lines
        return max(40, w), max(10, h)
    except Exception:
        return 80, 24


_init_w, _init_h = get_terminal_dimensions()
console = Console(theme=LAB_THEME, highlight=False, width=_init_w, height=_init_h)


def get_terminal_width() -> int:
    """Return the current terminal width, updating console dimensions."""
    w, h = get_terminal_dimensions()
    console._width = w
    console._height = h
    return w


def update_console_width() -> int:
    """Explicitly synchronize console.width with current terminal dimensions."""
    return get_terminal_width()


def is_narrow() -> bool:
    """Return True if terminal width is less than 90 columns."""
    return get_terminal_width() < 90


def is_wide() -> bool:
    """Return True if terminal width is at least 120 columns."""
    return get_terminal_width() >= 120


def clear_screen() -> None:
    """Clear terminal screen if running interactively."""
    if sys.stdout.isatty():
        os.system("clear" if os.name != "nt" else "cls")


def render_banner(system_info: Optional[Dict[str, Any]] = None) -> None:
    """Display the QSecure 2.0 laboratory branding and system status."""
    term_width = get_terminal_width()
    
    # ASCII Art Header adapted to terminal width
    if term_width >= 75:
        banner_raw = [
            "  ██████╗  ███████╗ ███████╗  ██████╗ ██╗   ██╗ ██████╗  ███████╗  ██████╗  ",
            " ██╔═══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██║   ██║ ██╔══██╗ ██╔════╝ ██╔════╝  ",
            " ██║   ██║ ███████╗ █████╗   ██║      ██║   ██║ ██████╔╝ █████╗   ███████╗  ",
            " ██║▄▄ ██║ ╚════██║ ██╔══╝   ██║      ██║   ██║ ██╔══██╗ ██╔══╝   ╚════██║  ",
            " ╚██████╔╝ ███████║ ███████╗ ╚██████╗ ╚██████╔╝ ██║  ██║ ███████╗ ██████╔╝  ",
            "  ╚══▀▀═╝  ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝ ╚══════╝ ╚═════╝   ",
        ]
        banner_text = Text("\n".join(banner_raw), style="bold cyan")
    else:
        banner_text = Text("== Q S E C U R E   2 . 0 ==", style="bold cyan")

    subtitle = Text(
        "Quantum-Resilient Cryptographic Orchestration & Comparative Benchmarking Suite",
        style="bold magenta",
    )
    nodes_line = Text("Dual-Node Cryptographic Simulator: Alice (Node A) <-> Bob (Node B)", style="dim white")

    meta_parts = []
    if system_info:
        cpu = system_info.get("cpu_model", "Unknown CPU")
        cores = system_info.get("cpu_cores", "N/A")
        py_ver = system_info.get("python_version", sys.version.split()[0])
        os_name = system_info.get("os_name", os.name)
        meta_parts.append(f"Host: {os_name} | CPU: {cpu} ({cores} cores) | Python: {py_ver}")
    meta_parts.append(f"Terminal: {term_width} cols")
    meta_text = Text(" • ".join(meta_parts), style="dim cyan")

    content = Group(
        Align.center(banner_text),
        Align.center(subtitle),
        Align.center(nodes_line),
        Align.center(meta_text),
    )

    console.print(Panel(content, box=ROUNDED, border_style="grey35", padding=(0, 1)))


def render_header(title: str, subtitle: Optional[str] = None, style: str = "bold cyan") -> None:
    """Render a section header with border and optional subtitle."""
    width = get_terminal_width()
    t = Text(f" {title.upper()} ", style=style)
    if subtitle:
        sub_text = Text(f"\n {subtitle}", style="dim white")
        console.print(Panel(Group(t, sub_text), box=ROUNDED, border_style="grey35"))
    else:
        console.print(Panel(Align.center(t), box=ROUNDED, border_style="grey35"))


def render_status_pill(status: str) -> Text:
    """Generate a high-visibility status badge."""
    s = status.upper().strip()
    if s in ("PASS", "OK", "SUCCESS", "VERIFIED"):
        return Text(" PASS ", style="pass")
    elif s in ("FAIL", "ERROR", "MISMATCH"):
        return Text(" FAIL ", style="fail")
    elif s in ("WARNING", "WARN", "PENDING", "DEGRADED"):
        return Text(" WARN ", style="warn_badge")
    elif s in ("THEORETICAL", "THEORY", "ANALYSIS"):
        return Text(" THEORY ", style="theo_badge")
    elif s in ("MEASURED", "EMPIRICAL", "BENCHMARK"):
        return Text(" MEASURED ", style="meas_badge")
    elif s in ("SIMULATED", "MODEL"):
        return Text(" SIMULATED ", style="warn_badge")
    elif s in ("UNSUPPORTED", "NOT TESTED"):
        return Text(" NOT TESTED ", style="dimmed")
    return Text(f" {s} ", style="highlight")


def render_step_status(step_num: int | str, title: str, detail: str, status: str = "OK") -> None:
    """Print an aligned execution step status line."""
    pill = render_status_pill(status)
    t = Text()
    t.append(f" {step_num}. ", style="bold white")
    t.append(f"{title:<28} ", style="bold")
    t.append(": ", style="dim")
    t.append(detail, style="white")
    console.print(Group(pill, t) if is_narrow() else Text.assemble(pill, " ", t))


def render_bar_chart(
    items: List[Tuple[str, float]],
    unit: str = "ms",
    max_bar_width: int = 36,
    log_scale: bool = False,
) -> None:
    """Render a compact, aligned horizontal ASCII/Unicode bar chart.
    
    Handles wide dynamic ranges gracefully with optional logarithmic scaling.
    """
    if not items:
        return

    term_width = get_terminal_width()
    bar_width = min(max_bar_width, max(12, term_width - 45))

    import math

    vals = [val for _, val in items]
    max_val = max(vals) if vals else 1.0

    table = Table(box=SIMPLE, show_header=False, padding=(0, 1), collapse_padding=True)
    table.add_column("Label", style="bold", justify="left", no_wrap=True)
    table.add_column("Value", justify="right", style="cyan", no_wrap=True)
    table.add_column("Bar", justify="left")

    for label, val in items:
        if log_scale:
            # Safe log10 scale
            norm = math.log10(max(val, 0.001) + 1) / math.log10(max(max_val, 0.001) + 1)
        else:
            norm = (val / max_val) if max_val > 0 else 0.0

        bar_len = int(round(norm * bar_width))
        bar_len = max(1 if val > 0 else 0, min(bar_width, bar_len))
        
        # Color coding by protocol if detected
        color = "cyan"
        if "CKD" in label.upper() or "CLASSICAL" in label.upper():
            color = "dodger_blue1"
        elif "MKD" in label.upper() or "ML-KEM" in label.upper() or "PQC" in label.upper():
            color = "magenta"
        elif "QKD" in label.upper() or "QUANTUM" in label.upper():
            color = "cyan"

        bar_str = "█" * bar_len + "░" * (bar_width - bar_len)
        bar_text = Text(bar_str, style=color)
        val_str = f"{val:,.2f} {unit}"
        table.add_row(label, val_str, bar_text)

    console.print(table)


def render_latency_plot(delays: List[int], data_series: Dict[str, List[float]]) -> None:
    """Render a clear multi-protocol ASCII chart showing latency scaling."""
    term_width = get_terminal_width()
    available_width = min(40, max(15, term_width - 35))

    # Find global max for normalization
    all_vals = [v for s in data_series.values() for v in s]
    max_v = max(all_vals) if all_vals else 1.0

    table = Table(
        title="Key Establishment Latency Scaling vs Network Delay",
        box=ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Delay (ms)", justify="right", style="bold white")
    for name in data_series.keys():
        col_style = "dodger_blue1" if "CKD" in name else ("magenta" if "ML-KEM" in name or "MKD" in name else "cyan")
        table.add_column(f"{name} (ms)", justify="right", style=col_style)
    table.add_column("Visual Scaling [CKD:Blue | ML-KEM:Mag | QKD:Cyan]", justify="left")

    for i, delay in enumerate(delays):
        row = [f"{delay} ms"]
        bars = []
        for name, vals in data_series.items():
            val = vals[i] if i < len(vals) else 0.0
            row.append(f"{val:,.1f}")
            # Mini bar component
            pct = int((val / max_v) * available_width) if max_v > 0 else 0
            char = "■" if "CKD" in name else ("▲" if "ML-KEM" in name or "MKD" in name else "◆")
            style = "dodger_blue1" if "CKD" in name else ("magenta" if "ML-KEM" in name or "MKD" in name else "cyan")
            bars.append(Text(f"{char * max(1, pct)}", style=style))

        bar_composite = Text(" ")
        for b in bars:
            bar_composite.append_text(b)
            bar_composite.append(" ")
        row.append(bar_composite)
        table.add_row(*row)

    console.print(table)


def wait_for_enter(prompt: str = "Press Enter to return to menu...") -> None:
    """Prompt the user to press Enter to continue."""
    try:
        console.print(f"\n[dim]{prompt}[/dim]", end="")
        input()
    except (KeyboardInterrupt, EOFError):
        pass
