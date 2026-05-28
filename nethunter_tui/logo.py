"""ANSI color constants and display helpers for the Nethunter TUI."""

import shutil


class C:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[101m"
    BG_GREEN = "\033[102m"
    BG_YELLOW = "\033[103m"
    BG_BLUE = "\033[104m"
    BG_MAGENTA = "\033[105m"
    BG_CYAN = "\033[106m"


# ── Gradient Logo ──────────────────────────────────────────────────────────

LOGO_LINES = [
    f"{C.RED}███╗   ██╗███████╗████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ {C.RESET}",
    f"{C.RED}████╗  ██║██╔════╝╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{C.RESET}",
    f"{C.YELLOW}██╔██╗ ██║█████╗     ██║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{C.RESET}",
    f"{C.GREEN}██║╚██╗██║██╔══╝     ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{C.RESET}",
    f"{C.CYAN}██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{C.RESET}",
    f"{C.MAGENTA}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}",
]


def print_logo() -> None:
    """Print the gradient NETHUNTER block-art logo."""
    cols = shutil.get_terminal_size().columns
    for line in LOGO_LINES:
        stripped = line.replace(C.RESET, "").lstrip("\033[9")
        visible_len = len(stripped) - 4  # approximate
        pad = max(0, (cols - visible_len) // 2)
        print(" " * pad + line)


# ── Formatting helpers ─────────────────────────────────────────────────────


def banner(text: str, color: str = C.CYAN, width: int = 60) -> str:
    """Return a centred banner with unicode box characters."""
    inner = f" {text} ".center(width - 2)
    top = f"{color}╔{'═' * (width - 2)}╗{C.RESET}"
    mid = f"{color}║{C.BOLD}{inner}{C.RESET}{color}║{C.RESET}"
    bot = f"{color}╚{'═' * (width - 2)}╝{C.RESET}"
    return f"{top}\n{mid}\n{bot}"


def info_box(items: list, color: str = C.CYAN) -> str:
    """Render a simple indented info box with key-value pairs."""
    lines = []
    for label, value in items:
        lines.append(f"  {color}{label}:{C.RESET} {value}")
    return "\n".join(lines)


def colorize(text: str, color: str = C.CYAN) -> str:
    """Wrap text in a color and reset."""
    return f"{color}{text}{C.RESET}"


def status_bar(text: str, color: str = C.CYAN) -> str:
    """Return a centered status bar line."""
    cols = shutil.get_terminal_size().columns
    inner = f" {text} "
    pad = max(0, cols - len(inner) - 2)
    return f"{color}{'─' * (pad // 2)}{inner}{'─' * (pad - pad // 2)}{C.RESET}"
