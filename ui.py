#!/usr/bin/env python3
"""
============================================================
UI MODUL - Tampilan OSINT Toolkit
============================================================
Tampilan CLI dengan box-drawing characters dan warna ANSI.
Otomatis menonaktifkan warna jika terminal tidak mendukung.

Author : OSINT Toolkit
Versi  : 1.0
============================================================
"""

import sys
import os


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Neon base
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    # Neon bright (cyberpunk)
    BRED    = "\033[91m"      # Neon red alert
    BGREEN  = "\033[92m"      # Neon green matrix
    BYELLOW = "\033[93m"      # Electric yellow
    BBLUE   = "\033[94m"      # Electric blue
    BMAGENTA= "\033[95m"      # Neon pink / magenta
    BCYAN   = "\033[96m"      # Neon cyan
    BWHITE  = "\033[97m"      # Pure white

    # Cyberpunk role colors
    NEON_PINK   = BMAGENTA    # Primary brand
    NEON_CYAN   = BCYAN       # Secondary accent
    NEON_GREEN  = BGREEN      # Success / matrix
    NEON_YELLOW = BYELLOW     # Warning / highlight
    NEON_RED    = BRED        # Error / danger


BOX = {
    "h":  "─",
    "v":  "│",
    "tl": "┌",
    "tr": "┐",
    "bl": "└",
    "br": "┘",
    "vl": "├",
    "vr": "┤",
    "vt": "┬",
    "vb": "┴",
    "cx": "┼",
}



try:
    "\U0001F430".encode("utf-8")
    EMOJI = True
except Exception:
    EMOJI = False

ICON = {
    "menu":    "📋" if EMOJI else "[MENU]",
    "info":    "🔍" if EMOJI else "[INFO]",
    "success": "✅" if EMOJI else "[OK]",
    "error":   "❌" if EMOJI else "[ERR]",
    "warning": "⚠️ " if EMOJI else "[!]",
    "target":  "🎯" if EMOJI else "[TARGET]",
    "domain":  "🌐" if EMOJI else "[DOM]",
    "ip":      "📡" if EMOJI else "[IP]",
    "time":    "⏱️ " if EMOJI else "[TIME]",
    "save":    "💾" if EMOJI else "[SAVE]",
    "exit":    "🚪" if EMOJI else "[EXIT]",
    "net":     "🌐" if EMOJI else "[NET]",
    "lock":    "🔒" if EMOJI else "[SSL]",
    "port":    "🔌" if EMOJI else "[PORT]",
    "user":    "👤" if EMOJI else "[USER]",
    "cert":    "📜" if EMOJI else "[CERT]",
    "dns":     "📡" if EMOJI else "[DNS]",
    "whois":   "📋" if EMOJI else "[WHOIS]",
    "web":     "🌐" if EMOJI else "[WEB]",
    "sub":     "🔎" if EMOJI else "[SUB]",
    "banner":  "🏷️ " if EMOJI else "[BANNER]",
    "geo":     "📍" if EMOJI else "[GEO]",
    "back":    "🔙" if EMOJI else "[BACK]",
    "rocket":  "🚀" if EMOJI else "[RUN]",
    "gear":    "⚙️ " if EMOJI else "[CFG]",
    "search":  "🔍" if EMOJI else "[SRC]",
    "shield":  "🛡️ " if EMOJI else "[SHLD]",
    "bolt":    "⚡" if EMOJI else "[BOLT]",
    "fire":    "🔥" if EMOJI else "[FIRE]",
    "sparkle": "✨" if EMOJI else "[DONE]",
}



def supports_color():
    if not sys.stdout.isatty():
        return False
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 0
    except Exception:
        return os.environ.get("TERM", "") != "dumb"


USE_COLOR = supports_color()


def c(text, color):
    if USE_COLOR:
        return "{}{}{}".format(color, text, C.RESET)
    return text


HASIL_DIR = "hasil"


def ensure_hasil_dir():
    """Buat folder hasil jika belum ada."""
    if not os.path.isdir(HASIL_DIR):
        os.makedirs(HASIL_DIR, exist_ok=True)
    return HASIL_DIR


def get_hasil_path(nama_file):
    """Kembalikan path lengkap di folder hasil."""
    ensure_hasil_dir()
    return os.path.join(HASIL_DIR, nama_file)


# ---------------------------------------------------------------------------
# Banner ASCII Art
# ---------------------------------------------------------------------------
BANNER = r"""
██████╗ ███████╗██╗███╗   ██╗████████╗              ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝              ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║███████╗██║██╔██╗ ██║   ██║       █████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║   ██║╚════██║██║██║╚██╗██║   ██║       ╚════╝    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╔╝███████║██║██║ ╚████║   ██║                 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝                 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""


def tampilkan_banner(color=C.BMAGENTA):
    print(c(BANNER, color))
    print(c("                          By ViZuann", C.BOLD + C.YELLOW))
    print()


# ---------------------------------------------------------------------------
# Helper tampilan
# ---------------------------------------------------------------------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def line(char=BOX["h"], width=60, color=C.NEON_CYAN):
    print(c(char * width, color))


def header(title="OSINT HUNTER v2.0", subtitle="Open Source Intelligence", width=60):
    tampilkan_banner()
    # Efek neon glow pada judul utama
    print(c("  {} {}".format(ICON["menu"], title), C.BOLD + C.NEON_PINK))
    print(c("  {} {}".format(ICON["info"], subtitle), C.BOLD + C.NEON_CYAN))
    line(color=C.NEON_PINK)
    print()


def section(title, icon="info", width=60, color=C.NEON_PINK):
    print()
    pad = (width - len(title) - 4) // 2
    left = BOX["h"] * max(pad, 1)
    right = BOX["h"] * max(width - len(title) - 4 - pad, 1)
    print(c("{} {} {} {}".format(left, ICON.get(icon, ICON["info"]), title, right),
            C.BOLD + color))
    print()


def menu_item(num, text, icon="", color=C.NEON_CYAN, num_color=C.NEON_YELLOW):
    n = c("[{}]".format(num), num_color)
    t = c(text, color)
    i = c(ICON.get(icon, ""), C.DIM + C.NEON_CYAN) if icon else ""
    print("    {}  {} {}".format(n, i, t))


def success(msg):
    print("  {} {}".format(c(ICON["success"], C.NEON_GREEN), c(msg, C.NEON_GREEN)))


def error(msg):
    print("  {} {}".format(c(ICON["error"], C.NEON_RED), c(msg, C.NEON_RED)))


def info(msg):
    print("  {} {}".format(c(ICON["info"], C.NEON_CYAN), c(msg, C.NEON_CYAN)))


def warning(msg):
    print("  {} {}".format(c(ICON["warning"], C.NEON_YELLOW), c(msg, C.NEON_YELLOW)))


def result(key, value, key_color=C.NEON_CYAN, val_color=C.BWHITE):
    print("    {} : {}".format(c(key, key_color), c(value, val_color)))


def box(title, lines, width=60, color=C.NEON_CYAN):
    print(c(BOX["tl"] + BOX["h"] * (width - 2) + BOX["tr"], color))
    if title:
        t = " {} ".format(title)
        pad = width - len(t) - 2
        print(c(BOX["v"], color) + " " + c(t, C.BOLD + C.NEON_PINK) + " " +
              BOX["h"] * max(pad, 1) + c(BOX["v"], color))
        print(c(BOX["vl"] + BOX["h"] * (width - 2) + BOX["vr"], color))
    for line_text in lines:
        print(c(BOX["v"], color) + " " + line_text.ljust(width - 4) + " " +
              c(BOX["v"], color))
    print(c(BOX["bl"] + BOX["h"] * (width - 2) + BOX["br"], color))


def prompt(text, color=C.NEON_YELLOW):
    return input(c("{} {} ".format(ICON["info"], text), color)).strip()


def confirm(text="Lanjutkan?", color=C.NEON_YELLOW):
    jawab = input(c("{} {} (y/n): ".format(ICON["warning"], text), color)).strip().lower()
    return jawab == "y"


def footer(msg="Selesai.", icon="sparkle"):
    print()
    line(color=C.NEON_PINK)
    print(c("  {} {}".format(ICON.get(icon, ICON["sparkle"]), msg),
            C.BOLD + C.NEON_PINK))
    line(color=C.NEON_PINK)
    print(c("           OSINT HUNTER v2.0 - By ViZuann", C.BOLD + C.NEON_CYAN))
    print()


def loading(msg="Memproses", duration=3, color=C.CYAN):
    import time
    for i in range(duration):
        dots = "." * (i % 4)
        print(c("\r  {} {}{}".format(ICON["info"], msg, dots), color),
              end="", flush=True)
        time.sleep(0.5)
    print(c("\r{}\r".format(" " * (len(msg) + 10)), C.RESET), end="", flush=True)
