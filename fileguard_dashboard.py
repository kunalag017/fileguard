import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import hashlib
from datetime import datetime
import math

# ==================== COLORS ====================

BG = "#B99AF6"
PANEL = "#07060B"
PANEL2 = "#110D1C"
PURPLE = "#8B4DFF"
PURPLE_BRIGHT = "#B56CFF"
LILAC = "#D8C5FF"
WHITE = "#F7F3FF"
MUTED = "#A79ABF"
GREEN = "#68E6B0"
RED = "#FF6B9D"
LINE = "#30213F"

# ==================== APPLICATION ====================

root = tk.Tk()
root.title("FileGuard | Integrity Monitor")
root.geometry("1280x820")
root.minsize(1050, 700)
root.configure(bg=BG)

selected_file = None
baseline_hash = None
events = []
verify_count = 0

# ==================== VARIABLES ====================

selected_path_var = tk.StringVar(value="No file selected")
name_var = tk.StringVar(value="—")
size_var = tk.StringVar(value="—")
current_hash_var = tk.StringVar(value="—")
status_var = tk.StringVar(value="WAITING FOR FILE")
status_detail_var = tk.StringVar(
    value="Select a file to begin an integrity check."
)
verify_count_var = tk.StringVar(value="0")

# ==================== HASHING ====================

def file_hash(path):
    """Calculate the SHA-256 hash of a file."""
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.1f} KB"
    elif size < 1024**3:
        return f"{size / (1024**2):.2f} MB"
    return f"{size / (1024**3):.2f} GB"


# ==================== ACTIVITY LOG ====================

def add_event(message, kind="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    events.insert(0, (timestamp, message, kind))
    del events[8:]
    refresh_activity()


def refresh_activity():
    for child in activity_inner.winfo_children():
        child.destroy()

    if not events:
        tk.Label(
            activity_inner,
            text="No activity yet — select a file to begin.",
            bg=PANEL,
            fg=MUTED,
            font=("Helvetica", 10)
        ).pack(anchor="w", pady=8)
        return

    for time_text, message, kind in events:
        row = tk.Frame(activity_inner, bg=PANEL)
        row.pack(fill="x", pady=5)

        if kind == "success":
            dot_color = GREEN
        elif kind == "danger":
            dot_color = RED
        else:
            dot_color = PURPLE_BRIGHT

        tk.Label(
            row,
            text="●",
            fg=dot_color,
            bg=PANEL,
            font=("Helvetica", 9)
        ).pack(side="left", padx=(0, 8))

        tk.Label(
            row,
            text=time_text,
            fg=MUTED,
            bg=PANEL,
            font=("Helvetica", 9),
            width=8,
            anchor="w"
        ).pack(side="left")

        tk.Label(
            row,
            text=message,
            fg=WHITE,
            bg=PANEL,
            font=("Helvetica", 10),
            anchor="w",
            wraplength=360,
            justify="left"
        ).pack(side="left", fill="x", expand=True)


# ==================== FILE OPERATIONS ====================

def choose_file():
    global selected_file

    path = filedialog.askopenfilename(
        title="Choose a file to monitor"
    )

    if not path:
        return

    selected_file = Path(path)

    try:
        selected_path_var.set(str(selected_file))
        name_var.set(selected_file.name)
        size_var.set(format_size(selected_file.stat().st_size))
        current_hash_var.set(file_hash(selected_file))

        status_var.set("FILE SELECTED")
        status_detail_var.set(
            "Register a baseline to start monitoring."
        )
        status_dot.config(fg=PURPLE_BRIGHT)

        add_event(f"Selected {selected_file.name}", "info")

    except OSError as exc:
        messagebox.showerror(
            "FileGuard",
            f"Could not read this file:\n{exc}"
        )


def register_baseline():
    global baseline_hash

    if not selected_file:
        messagebox.showinfo(
            "Select a file",
            "Choose a file first."
        )
        return

    try:
        baseline_hash = file_hash(selected_file)
        current_hash_var.set(baseline_hash)

        status_var.set("BASELINE REGISTERED")
        status_detail_var.set(
            "Original fingerprint saved for this session."
        )
        status_dot.config(fg=GREEN)

        add_event(
            f"Baseline registered for {selected_file.name}",
            "success"
        )

    except OSError as exc:
        messagebox.showerror(
            "FileGuard",
            f"Could not register this file:\n{exc}"
        )


def verify_integrity():
    global verify_count

    if not selected_file:
        messagebox.showinfo(
            "Select a file",
            "Choose a file first."
        )
        return

    if baseline_hash is None:
        messagebox.showinfo(
            "Register baseline",
            "Register the baseline before verifying integrity."
        )
        return

    verify_count += 1
    verify_count_var.set(str(verify_count))
    ring.itemconfig(verify_count_text, text=str(verify_count))

    try:
        if not selected_file.exists():
            status_var.set("FILE MISSING")
            status_detail_var.set(
                "The selected file cannot be found at its original path."
            )
            status_dot.config(fg=RED)

            add_event(
                f"File missing: {selected_file.name}",
                "danger"
            )
            return

        new_hash = file_hash(selected_file)
        current_hash_var.set(new_hash)

        if new_hash == baseline_hash:
            status_var.set("INTEGRITY VERIFIED")
            status_detail_var.set(
                "Current hash matches the registered baseline."
            )
            status_dot.config(fg=GREEN)

            add_event(
                f"Integrity verified: {selected_file.name}",
                "success"
            )

        else:
            status_var.set("CHANGE DETECTED")
            status_detail_var.set(
                "Hash mismatch — the file contents have changed."
            )
            status_dot.config(fg=RED)

            add_event(
                f"Change detected in {selected_file.name}",
                "danger"
            )

    except OSError as exc:
        messagebox.showerror(
            "FileGuard",
            f"Could not verify this file:\n{exc}"
        )


def clear_session():
    global selected_file, baseline_hash, verify_count

    selected_file = None
    baseline_hash = None
    verify_count = 0

    selected_path_var.set("No file selected")
    name_var.set("—")
    size_var.set("—")
    current_hash_var.set("—")
    verify_count_var.set("0")
    ring.itemconfig(verify_count_text, text="0")

    status_var.set("WAITING FOR FILE")
    status_detail_var.set(
        "Select a file to begin an integrity check."
    )
    status_dot.config(fg=MUTED)

    events.clear()
    refresh_activity()


# ==================== UI HELPERS ====================

def label(
    parent,
    text,
    fg=WHITE,
    bg=PANEL,
    size=10,
    bold=False,
    **kwargs
):
    return tk.Label(
        parent,
        text=text,
        fg=fg,
        bg=bg,
        font=(
            "Helvetica",
            size,
            "bold" if bold else "normal"
        ),
        **kwargs
    )


def panel(parent, title, subtitle=None):
    frame = tk.Frame(
        parent,
        bg=PANEL,
        highlightthickness=1,
        highlightbackground=LINE
    )

    if title:
        head = tk.Frame(frame, bg=PANEL)
        head.pack(fill="x", padx=18, pady=(16, 0))

        label(
            head,
            title,
            size=12,
            bold=True
        ).pack(side="left")

        if subtitle:
            label(
                head,
                subtitle,
                fg=MUTED,
                size=9
            ).pack(side="right")

    return frame


def make_button(parent, text, command, primary=False):
    bg = PURPLE if primary else PANEL2
    fg = WHITE if primary else LILAC

    button = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=PURPLE_BRIGHT,
        activeforeground=WHITE,
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Helvetica", 10, "bold"),
        padx=15,
        pady=10,
        highlightthickness=0
    )

    button.bind(
        "<Enter>",
        lambda event: button.config(
            bg=PURPLE_BRIGHT if primary else "#211631"
        )
    )

    button.bind(
        "<Leave>",
        lambda event: button.config(bg=bg)
    )

    return button


# ==================== MAIN LAYOUT ====================

outer = tk.Frame(root, bg=BG)
outer.pack(fill="both", expand=True, padx=24, pady=22)

# Header
top = tk.Frame(outer, bg=BG)
top.pack(fill="x", pady=(0, 18))

brand = tk.Frame(top, bg=BG)
brand.pack(side="left")

logo = tk.Canvas(
    brand,
    width=42,
    height=42,
    bg=BG,
    highlightthickness=0
)
logo.pack(side="left", padx=(0, 10))

logo.create_oval(
    4, 4, 38, 38,
    outline=PURPLE,
    width=2
)
logo.create_line(
    13, 21, 19, 27, 30, 14,
    fill=WHITE,
    width=2,
    capstyle="round",
    joinstyle="round"
)

label(
    brand,
    "FILEGUARD",
    fg=PANEL,
    bg=BG,
    size=18,
    bold=True
).pack(anchor="w")

label(
    brand,
    "FILE INTEGRITY MONITOR  /  SECURITY CONSOLE",
    fg="#4F3C76",
    bg=BG,
    size=8
).pack(anchor="w", pady=(2, 0))

label(
    top,
    datetime.now().strftime("%d %b %Y  •  %H:%M"),
    fg=PANEL,
    bg=BG,
    size=10
).pack(side="right", pady=8)

# Two-column layout
content = tk.Frame(outer, bg=BG)
content.pack(fill="both", expand=True)

content.grid_columnconfigure(0, weight=5, uniform="col")
content.grid_columnconfigure(1, weight=4, uniform="col")
content.grid_rowconfigure(0, weight=1)

left = tk.Frame(content, bg=BG)
left.grid(
    row=0,
    column=0,
    sticky="nsew",
    padx=(0, 12)
)

right = tk.Frame(content, bg=BG)
right.grid(
    row=0,
    column=1,
    sticky="nsew",
    padx=(12, 0)
)

# ==================== STATUS CARD ====================

hero = tk.Frame(
    left,
    bg=PANEL,
    highlightthickness=1,
    highlightbackground=LINE
)
hero.pack(fill="x", pady=(0, 14))

hero_top = tk.Frame(hero, bg=PANEL)
hero_top.pack(fill="x", padx=20, pady=(18, 10))

label(
    hero_top,
    "SYSTEM STATUS",
    size=10,
    fg=MUTED,
    bold=True
).pack(side="left")

label(
    hero_top,
    "● LIVE SESSION",
    size=9,
    fg=GREEN
).pack(side="right")

status_line = tk.Frame(hero, bg=PANEL)
status_line.pack(fill="x", padx=20)

status_dot = label(
    status_line,
    "●",
    fg=MUTED,
    size=20
)
status_dot.pack(side="left", padx=(0, 10))

tk.Label(
    status_line,
    textvariable=status_var,
    fg=WHITE,
    bg=PANEL,
    font=("Helvetica", 16, "bold")
).pack(side="left")

tk.Label(
    hero,
    textvariable=status_detail_var,
    fg=MUTED,
    bg=PANEL,
    font=("Helvetica", 10),
    anchor="w"
).pack(fill="x", padx=20, pady=(7, 18))

# ==================== FILE CARD ====================

file_card = panel(left, "MONITORED FILE", "SHA-256")
file_card.pack(fill="x", pady=(0, 14))

path_box = tk.Frame(file_card, bg=PANEL2)
path_box.pack(fill="x", padx=18, pady=(14, 12))

tk.Label(
    path_box,
    textvariable=selected_path_var,
    bg=PANEL2,
    fg=LILAC,
    font=("Helvetica", 9),
    anchor="w",
    padx=10,
    pady=10,
    wraplength=450,
    justify="left"
).pack(fill="x")

details = tk.Frame(file_card, bg=PANEL)
details.pack(fill="x", padx=18, pady=(0, 12))

for col, (title, variable) in enumerate([
    ("FILE NAME", name_var),
    ("FILE SIZE", size_var)
]):
    cell = tk.Frame(details, bg=PANEL)
    cell.grid(row=0, column=col, sticky="ew", padx=(0, 12))

    label(cell, title, fg=MUTED, size=8).pack(anchor="w")

    tk.Label(
        cell,
        textvariable=variable,
        fg=WHITE,
        bg=PANEL,
        font=("Helvetica", 10, "bold"),
        anchor="w",
        wraplength=230
    ).pack(anchor="w", pady=(5, 0))

details.grid_columnconfigure(0, weight=2)
details.grid_columnconfigure(1, weight=1)

actions = tk.Frame(file_card, bg=PANEL)
actions.pack(fill="x", padx=18, pady=(0, 18))

make_button(
    actions,
    "＋  Select file",
    choose_file,
    primary=True
).pack(side="left", padx=(0, 8))

make_button(
    actions,
    "Register baseline",
    register_baseline
).pack(side="left", padx=(0, 8))

make_button(
    actions,
    "Verify",
    verify_integrity
).pack(side="left")

# ==================== HASH CARD ====================

hash_card = panel(left, "CURRENT FINGERPRINT", "SHA-256 HASH")
hash_card.pack(fill="both", expand=True)

tk.Label(
    hash_card,
    textvariable=current_hash_var,
    bg=PANEL,
    fg=PURPLE_BRIGHT,
    font=("Menlo", 9),
    anchor="w",
    justify="left",
    wraplength=500
).pack(fill="x", padx=18, pady=18)

label(
    hash_card,
    "A changed hash indicates the file differs from its baseline.",
    fg=MUTED,
    size=9
).pack(anchor="w", padx=18, pady=(0, 16))

# ==================== INTEGRITY OVERVIEW ====================

integrity = tk.Frame(
    right,
    bg=PANEL,
    highlightthickness=1,
    highlightbackground=LINE
)
integrity.pack(fill="x", pady=(0, 14))

integrity_head = tk.Frame(integrity, bg=PANEL)
integrity_head.pack(fill="x", padx=18, pady=(16, 0))

label(
    integrity_head,
    "INTEGRITY OVERVIEW",
    size=12,
    bold=True
).pack(side="left")

label(
    integrity_head,
    "SESSION",
    fg=MUTED,
    size=9
).pack(side="right")

ring = tk.Canvas(
    integrity,
    height=190,
    bg=PANEL,
    highlightthickness=0
)
ring.pack(fill="x", padx=10, pady=5)

cx, cy = 175, 92

for radius, color in [
    (67, "#41265F"),
    (57, "#6A3B99"),
    (47, PURPLE)
]:
    ring.create_oval(
        cx - radius,
        cy - radius,
        cx + radius,
        cy + radius,
        outline=color,
        width=1
    )

for i in range(72):
    angle = math.radians(i * 5)
    r1 = 72
    r2 = 78 if i % 3 == 0 else 75

    x1 = cx + math.cos(angle) * r1
    y1 = cy + math.sin(angle) * r1
    x2 = cx + math.cos(angle) * r2
    y2 = cy + math.sin(angle) * r2

    ring.create_line(
        x1, y1, x2, y2,
        fill=PURPLE_BRIGHT if i % 4 == 0 else "#65418B",
        width=1
    )

ring.create_text(
    cx, cy - 5,
    text="SHA-256",
    fill=MUTED,
    font=("Helvetica", 9)
)

ring.create_text(
    cx, cy + 15,
    text="READY",
    fill=WHITE,
    font=("Helvetica", 16, "bold")
)

ring.create_text(
    310, 75,
    text="BASELINE",
    fill=MUTED,
    font=("Helvetica", 8)
)

ring.create_text(
    310, 96,
    text="—",
    fill=PURPLE_BRIGHT,
    font=("Helvetica", 16, "bold")
)

ring.create_text(
    310, 121,
    text="VERIFICATIONS",
    fill=MUTED,
    font=("Helvetica", 8)
)

verify_count_text = ring.create_text(
    310, 143,
    text="0",
    fill=WHITE,
    font=("Helvetica", 15, "bold")
)

# ==================== QUICK WORKFLOW ====================

how = panel(right, "QUICK WORKFLOW", "3 STEPS")
how.pack(fill="x", pady=(0, 14))

workflow = [
    ("01", "Choose a file", "Pick the file you want to monitor."),
    ("02", "Register baseline", "Save its original SHA-256 fingerprint."),
    ("03", "Verify integrity", "Compare the current hash with the baseline.")
]

for number, heading, description in workflow:
    row = tk.Frame(how, bg=PANEL)
    row.pack(fill="x", padx=18, pady=(13, 0))

    tk.Label(
        row,
        text=number,
        fg=PURPLE_BRIGHT,
        bg=PANEL,
        font=("Menlo", 11, "bold"),
        width=4,
        anchor="w"
    ).pack(side="left", anchor="n")

    text_col = tk.Frame(row, bg=PANEL)
    text_col.pack(side="left", fill="x", expand=True)

    label(text_col, heading, size=10, bold=True).pack(anchor="w")

    label(
        text_col,
        description,
        size=9,
        fg=MUTED
    ).pack(anchor="w", pady=(3, 0))

label(
    how,
    "Tip: edit a test file after registering its baseline, then verify it.",
    fg="#BFA9E5",
    size=9,
    bg=PANEL,
    wraplength=420,
    justify="left"
).pack(anchor="w", padx=18, pady=15)

# ==================== RECENT ACTIVITY ====================

activity = panel(right, "RECENT ACTIVITY", "LATEST EVENTS")
activity.pack(fill="both", expand=True)

activity_inner = tk.Frame(activity, bg=PANEL)
activity_inner.pack(fill="both", expand=True, padx=18, pady=(8, 14))

refresh_activity()

# ==================== BOTTOM BAR ====================

bottom = tk.Frame(outer, bg=BG)
bottom.pack(fill="x", pady=(14, 0))

label(
    bottom,
    "FILEGUARD  •  LOCAL FILE CHECKS  •  SHA-256",
    fg="#4F3C76",
    bg=BG,
    size=8
).pack(side="left")

make_button(
    bottom,
    "Reset session",
    clear_session
).pack(side="right")

# ==================== START APPLICATION ====================

root.mainloop()
