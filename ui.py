import customtkinter as ctk
from tkinter import messagebox
import pyperclip
import os

from auth import (
    verify_master_password,
    set_master_password_ui,
    change_master_password,
)
from storage import add_entry, get_all_sites, get_entry, delete_entry, export_passwords, import_passwords
from password_generator import generate_password
import session
import customtkinter as ctk
from storage import auto_backup
import threading



# === UI SETTINGS ===
from utils import load_theme_preference, save_theme_preference

# Load saved theme
saved_theme = load_theme_preference()
ctk.set_appearance_mode(saved_theme)
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Offline Password Manager")
app.geometry("750x550")
app.resizable(False, False)


# ---------- LOGIN ----------
def show_login_screen():
    for widget in app.winfo_children():
        widget.destroy()

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=80, fill="both", expand=True)

    ctk.CTkLabel(frame, text="🔐 Offline Password Manager", font=("Arial", 24, "bold")).pack(pady=(20, 5))
    ctk.CTkLabel(frame, text="Enter your master password to unlock", font=("Arial", 14)).pack(pady=(0, 20))

    password_entry = ctk.CTkEntry(frame, show="*", width=280, height=40, placeholder_text="Master Password")
    password_entry.pack(pady=10)

    error_label = ctk.CTkLabel(frame, text="", text_color="red")
    error_label.pack(pady=5)

    def check_login():
        entered_password = password_entry.get()
        result = verify_master_password(entered_password)

        if result is True:
            session.current_master_password = entered_password  # store globally in session
            show_dashboard()
            start_session_monitor()

        elif result is None:
            messagebox.showinfo("Setup", "No master password found. Please create one.")
            show_set_master_ui()
        else:
            error_label.configure(text="❌ Incorrect password!")


    # --- Buttons ---
    ctk.CTkButton(frame, text="Login", width=200, height=40, command=check_login).pack(pady=10)

    # Show "Set Master Password" only if no master.key exists
    if not os.path.exists("master.key"):
        ctk.CTkButton(frame, text="Set Master Password", width=200, command=show_set_master_ui).pack(pady=5)

    ctk.CTkButton(frame, text="Forgot Password?", fg_color="gray", width=200, command=forgot_password_ui).pack(pady=5)


# ---------- SET MASTER PASSWORD ----------
def show_set_master_ui():
    for widget in app.winfo_children():
        widget.destroy()

    from utils import show_password_strength

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=80, fill="both", expand=True)

    # --- Title ---
    ctk.CTkLabel(frame, text="🛡️ Set Master Password", font=("Arial", 24, "bold")).pack(pady=(20, 5))
    ctk.CTkLabel(frame, text="Create a strong password to secure your vault", font=("Arial", 14)).pack(pady=(0, 10))

    # --- Warning Label (starts invisible) ---
    warning_label = ctk.CTkLabel(
        frame,
        text="⚠️ Warning: If you forget your master password,\nthere is *no way* to recover your data!",
        font=("Arial", 13, "italic"),
        text_color=("gray70", "gray70")  # start dim
    )
    warning_label.pack(pady=(0, 20))

    # --- Fade-in Effect for Warning ---
    def fade_in(step=0):
        colors = [
            "gray70", "gray60", "gray50", "gray40",
            "orange3", "orange2", "orange"
        ]
        if step < len(colors):
            warning_label.configure(text_color=colors[step])
            frame.after(150, fade_in, step + 1)

    fade_in()  # start the animation

    # --- Input Fields ---
    # Add password strength meter
    strength_label = ctk.CTkLabel(frame, text="", font=("Arial", 12))
    strength_label.pack(pady=5)

    password_entry = ctk.CTkEntry(frame, show="*", width=280, height=40, placeholder_text="Enter new master password")
    password_entry.pack(pady=8)

    def update_strength_meter(event=None):
        pwd = password_entry.get()
        strength_text, strength_color = show_password_strength(pwd)
        strength_label.configure(text=strength_text, text_color=strength_color)

    password_entry.bind("<KeyRelease>", update_strength_meter)

    confirm_entry = ctk.CTkEntry(frame, show="*", width=280, height=40, placeholder_text="Confirm master password")
    confirm_entry.pack(pady=8)

    message_label = ctk.CTkLabel(frame, text="", text_color="lightgray")
    message_label.pack(pady=5)

    # --- Button Action ---
    def set_password():
        result = set_master_password_ui(password_entry.get(), confirm_entry.get())
        message_label.configure(text=result)
        if "✅" in result:
            messagebox.showinfo("Success", "Master password set successfully!")
            show_login_screen()

    # --- Buttons ---
    ctk.CTkButton(frame, text="Set Password", width=200, height=40, command=set_password).pack(pady=10)
    ctk.CTkButton(frame, text="⬅ Back to Login", fg_color="gray", width=200, height=35, command=show_login_screen).pack(pady=5)

# ---------- DASHBOARD ----------
def show_dashboard():
    for widget in app.winfo_children():
        widget.destroy()

    # === Main Frame ===
    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=40, pady=20, fill="both", expand=True)

    # === Header ===
    header_frame = ctk.CTkFrame(frame, fg_color="transparent")
    header_frame.pack(fill="x", pady=(10, 0), padx=12)

    ctk.CTkLabel(header_frame, text="🔐 Password Vault", font=("Arial", 26, "bold")).pack(side="left")
    # Count of stored sites
    sites = get_all_sites() or []
    ctk.CTkLabel(header_frame, text=f" • {len(sites)} saved", font=("Arial", 12), text_color="gray").pack(side="left", padx=(8, 0))

    # Small session indicator
    session_indicator = ctk.CTkLabel(header_frame, text="● Session active", text_color="lightgreen", font=("Arial", 11))
    session_indicator.pack(side="right")

    ctk.CTkLabel(
        frame,
        text="Securely store and manage your credentials",
        font=("Arial", 12, "italic"),
        text_color="gray"
    ).pack(pady=(4, 14))

    btn_width = 240
    btn_height = 40

    # === Top Controls & Quick Search ===
    top_frame = ctk.CTkFrame(frame, fg_color="transparent")
    top_frame.pack(fill="x", padx=12, pady=(0, 10))

    # Left: primary actions
    left_actions = ctk.CTkFrame(top_frame, fg_color="transparent")
    left_actions.pack(side="left", anchor="n")

    ctk.CTkButton(left_actions, text="➕ Add Password", width=btn_width, height=btn_height,
                  fg_color="#28a745", hover_color="#218838", command=add_entry_ui).pack(pady=6)
    ctk.CTkButton(left_actions, text="👁️ View Passwords", width=btn_width, height=btn_height,
                  fg_color="#007bff", hover_color="#0056b3", command=view_entries_ui).pack(pady=6)

    # Right: settings and utilities
    right_actions = ctk.CTkFrame(top_frame, fg_color="transparent")
    right_actions.pack(side="right", anchor="n")

    ctk.CTkButton(right_actions, text="🚪 Logout", width=120, height=btn_height,
                  fg_color="#6c757d", hover_color="#5a6268", command=logout_user).pack(pady=6, padx=6)
    def toggle_theme():
        new_theme = "light" if ctk.get_appearance_mode().lower() == "dark" else "dark"
        ctk.set_appearance_mode(new_theme)
        save_theme_preference(new_theme)

    ctk.CTkButton(right_actions, text="🌓 Toggle Theme", width=120, height=btn_height,
                  fg_color="#343a40", hover_color="#23272b",
                  command=toggle_theme).pack(pady=6, padx=6)

    # === Quick Search / Quick Actions ===
    quick_frame = ctk.CTkFrame(frame, fg_color="transparent")
    quick_frame.pack(fill="x", padx=12, pady=(0, 10))

    search_entry = ctk.CTkEntry(quick_frame, placeholder_text="Search sites...", width=320)
    search_entry.pack(side="left", padx=(0, 8))

    site_box = ctk.CTkComboBox(quick_frame, values=sites if sites else ["(no entries)"], width=300)
    site_box.pack(side="left", padx=(0, 8))

    details_label = ctk.CTkLabel(quick_frame, text="", anchor="w", width=1, wraplength=300, justify="left")
    details_label.pack(side="left", padx=(8, 0))

    def refresh_sites():
        nonlocal sites
        sites = get_all_sites() or []
        site_box.configure(values=sites if sites else ["(no entries)"])
        # update count in header
        header_children = header_frame.winfo_children()
        if len(header_children) >= 2:
            # second child is count label
            header_children[1].configure(text=f" • {len(sites)} saved")

    def search_site():
        term = search_entry.get().strip().lower()
        filtered = [s for s in sites if term in s.lower()]
        site_box.configure(values=filtered if filtered else ["(no match)"])

    def show_site_details():
        site = site_box.get()
        if not site or site in ("(no entries)", "(no match)"):
            messagebox.showinfo("Info", "Please select a valid site.")
            return
        data = get_entry(site)
        if not data:
            details_label.configure(text="❌ Not found")
            return
        user, pwd = data.get("username", ""), data.get("password", "")
        details_label.configure(text=f"User: {user}\nPassword: {pwd}")

    def copy_site_password():
        site = site_box.get()
        if not site or site in ("(no entries)", "(no match)"):
            messagebox.showinfo("Info", "Please select a valid site.")
            return
        data = get_entry(site)
        if data and data.get("password"):
            pyperclip.copy(data["password"])
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    ctk.CTkButton(quick_frame, text="🔍", width=70, command=search_site).pack(side="left", padx=(8, 0))
    ctk.CTkButton(quick_frame, text="Open", width=70, command=show_site_details).pack(side="left", padx=(6, 0))
    ctk.CTkButton(quick_frame, text="📋 Copy", width=70, command=copy_site_password).pack(side="left", padx=(6, 0))

    # === Recent Entries Panel ===
    recent_frame = ctk.CTkFrame(frame, fg_color="transparent")
    recent_frame.pack(fill="both", expand=False, padx=12, pady=(6, 12))

    ctk.CTkLabel(recent_frame, text="Recent / Quick Access", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 6))

    recent_sites = list(reversed(sites))[:6] if sites else []
    if not recent_sites:
        ctk.CTkLabel(recent_frame, text="No recent entries. Add passwords to see them here.", text_color="gray").pack(anchor="w", pady=6)
    else:
        list_frame = ctk.CTkFrame(recent_frame, fg_color="transparent")
        list_frame.pack(fill="x")
        for s in recent_sites:
            row = ctk.CTkFrame(list_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=s, anchor="w").pack(side="left", padx=(4, 8))
            def make_copy(site_name):
                return lambda: (pyperclip.copy(get_entry(site_name)["password"]) if get_entry(site_name) else None,
                                messagebox.showinfo("Copied", f"Password for {site_name} copied to clipboard!"))
            def make_view(site_name):
                return lambda: (lambda data=get_entry(site_name): messagebox.showinfo(site_name, f"User: {data.get('username','')}\nPassword: {data.get('password','')}") if data else messagebox.showinfo("Not found", "Entry missing."))()
            ctk.CTkButton(row, text="Open", width=70, height=28, command=make_view(s)).pack(side="right", padx=(6, 4))
            ctk.CTkButton(row, text="Copy", width=70, height=28, command=make_copy(s)).pack(side="right")

    # === Actions Row (Export / Import / Change / Delete) ===
    actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
    actions_frame.pack(fill="x", padx=12, pady=(6, 8))

    ctk.CTkButton(actions_frame, text="📤 Export", width=140, height=36, fg_color="#17a2b8", hover_color="#117a8b",
                  command=lambda: (export_passwords(), refresh_sites())).pack(side="left", padx=6)
    ctk.CTkButton(actions_frame, text="📥 Import", width=140, height=36, fg_color="#6f42c1", hover_color="#59359c",
                  command=lambda: (import_passwords(), refresh_sites())).pack(side="left", padx=6)
    ctk.CTkButton(actions_frame, text="🔄 Change Master", width=160, height=36, fg_color="#ffc107", hover_color="#e0a800",
                  text_color="black", command=change_password_ui).pack(side="left", padx=6)
    ctk.CTkButton(actions_frame, text="🗑️ Delete Entry", width=140, height=36, fg_color="#dc3545", hover_color="#b02a37",
                  command=lambda: delete_entries_ui() if sites else messagebox.showinfo("Info", "No entries to delete.")).pack(side="left", padx=6)

    # --- Auto Backup Toggle ---
    ctk.CTkCheckBox(frame, text="Enable Daily Auto Backup", variable=auto_backup_var).pack(pady=(6, 8))

    # === Footer ===
    footer = ctk.CTkLabel(frame, text="Password Manager © 2025", font=("Arial", 10, "italic"), text_color="gray")
    footer.pack(side="bottom", pady=(6, 6))

    # Keep UI in sync after data-changing actions
    def refresh_dashboard():
        refresh_sites()
        # update recent sites block by simply reloading dashboard contents
        # (for simplicity we rebuild the dashboard)
        show_dashboard()

    # expose refresh to other UI pieces if needed
    app.refresh_dashboard = refresh_dashboard

# ---------- ADD PASSWORD ----------
def add_entry_ui():
    for widget in app.winfo_children():
        widget.destroy()

    from utils import show_password_strength

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=40, fill="both", expand=True)

    ctk.CTkLabel(frame, text="➕ Add New Password", font=("Arial", 22, "bold")).pack(pady=15)

    website_entry = ctk.CTkEntry(frame, placeholder_text="Website Name", width=300, height=35)
    website_entry.pack(pady=5)
    username_entry = ctk.CTkEntry(frame, placeholder_text="Username / Email", width=300, height=35)
    username_entry.pack(pady=5)

    pwd_frame = ctk.CTkFrame(frame)
    pwd_frame.pack(pady=5)

    # Add strength meter label
    strength_label = ctk.CTkLabel(frame, text="", font=("Arial", 12))
    strength_label.pack(pady=(0, 5))

    # Add password field and strength meter
    password_entry = ctk.CTkEntry(pwd_frame, placeholder_text="Password", width=220)
    password_entry.pack(side="left", padx=5)

    def update_strength_meter(event=None):
        pwd = password_entry.get()
        strength_text, strength_color = show_password_strength(pwd)
        strength_label.configure(text=strength_text, text_color=strength_color)
        strength_label.pack(pady=(5, 0))  # Ensure it's visible

    password_entry.bind("<KeyRelease>", update_strength_meter)

    def copy_password():
        pwd = password_entry.get()
        if pwd:
            pyperclip.copy(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    ctk.CTkButton(pwd_frame, text="📋 Copy", width=60, command=copy_password).pack(side="left", padx=5)

    include_symbol = ctk.BooleanVar(value=True)

    def generate_new():
        pwd = generate_password(length=12, include_symbols=include_symbol.get())
        password_entry.delete(0, "end")
        password_entry.insert(0, pwd)
        # Update strength meter after generating password
        update_strength_meter()

    ctk.CTkCheckBox(frame, text="Include Symbols", variable=include_symbol).pack(pady=3)
    ctk.CTkButton(frame, text="⚙️ Generate Password", width=200, command=generate_new).pack(pady=5)

    def save_entry():
        site, user, pwd = website_entry.get(), username_entry.get(), password_entry.get()
        if not site or not user or not pwd:
            messagebox.showerror("Error", "Please fill all fields!")
            return
        add_entry(site, user, pwd)
        messagebox.showinfo("Saved", f"Password for {site} added!")
        show_dashboard()

    ctk.CTkButton(frame, text="💾 Save", width=200, command=save_entry).pack(pady=10)
    ctk.CTkButton(frame, text="⬅ Back", width=200, fg_color="gray", command=show_dashboard).pack(pady=5)


# ---------- VIEW PASSWORDS ----------
def view_entries_ui():
    for widget in app.winfo_children():
        widget.destroy()

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=40, fill="both", expand=True)

    ctk.CTkLabel(frame, text="👁️ View Saved Passwords", font=("Arial", 22, "bold")).pack(pady=10)

    sites = get_all_sites()
    if not sites:
        ctk.CTkLabel(frame, text="No passwords stored yet.").pack(pady=10)
        ctk.CTkButton(frame, text="⬅ Back", command=show_dashboard).pack(pady=10)
        return

    search_entry = ctk.CTkEntry(frame, placeholder_text="Search site...", width=280)
    search_entry.pack(pady=5)

    site_box = ctk.CTkComboBox(frame, values=sites, width=280)
    site_box.pack(pady=5)

    def search_site():
        term = search_entry.get().lower()
        filtered = [s for s in sites if term in s.lower()]
        site_box.configure(values=filtered if filtered else ["No match"])

    ctk.CTkButton(frame, text="🔍 Search", width=150, command=search_site).pack(pady=5)

    output_label = ctk.CTkLabel(frame, text="", font=("Arial", 14))
    output_label.pack(pady=10)

    def show_selected():
        site = site_box.get()
        data = get_entry(site)
        if data:
            user, pwd = data["username"], data["password"]
            output_label.configure(text=f"🧑 User: {user}\n🔑 Password: {pwd}")
        else:
            output_label.configure(text="❌ Not found!")

    def copy_password():
        site = site_box.get()
        data = get_entry(site)
        if data:
            pyperclip.copy(data["password"])
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    ctk.CTkButton(frame, text="Show Password", width=160, command=show_selected).pack(pady=5)
    ctk.CTkButton(frame, text="📋 Copy Password", width=160, command=copy_password).pack(pady=5)
    ctk.CTkButton(frame, text="⬅ Back", width=160, fg_color="gray", command=show_dashboard).pack(pady=10)


# ---------- DELETE PASSWORD ----------
def delete_entries_ui():
    for widget in app.winfo_children():
        widget.destroy()

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=40, fill="both", expand=True)

    ctk.CTkLabel(frame, text="🗑️ Delete Password", font=("Arial", 22, "bold")).pack(pady=10)

    sites = get_all_sites()
    if not sites:
        ctk.CTkLabel(frame, text="No saved passwords.").pack(pady=10)
        ctk.CTkButton(frame, text="⬅ Back", command=show_dashboard).pack(pady=10)
        return

    site_box = ctk.CTkComboBox(frame, values=sites, width=280)
    site_box.pack(pady=10)

    def delete_selected():
        site = site_box.get()
        if messagebox.askyesno("Confirm", f"Delete password for {site}?"):
            delete_entry(site)
            messagebox.showinfo("Deleted", f"Password for {site} deleted!")
            show_dashboard()

    ctk.CTkButton(frame, text="🗑️ Delete", width=160, command=delete_selected).pack(pady=5)
    ctk.CTkButton(frame, text="⬅ Back", width=160, fg_color="gray", command=show_dashboard).pack(pady=10)


# ---------- CHANGE MASTER PASSWORD ----------
def change_password_ui():
    for widget in app.winfo_children():
        widget.destroy()

    from utils import show_password_strength

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=80, fill="both", expand=True)

    ctk.CTkLabel(frame, text="Change Master Password", font=("Arial", 22, "bold")).pack(pady=20)

    old_entry = ctk.CTkEntry(frame, show="*", placeholder_text="Current password", width=280, height=35)
    old_entry.pack(pady=5)
    new_entry = ctk.CTkEntry(frame, show="*", placeholder_text="New password", width=280, height=35)
    new_entry.pack(pady=5)
    confirm_entry = ctk.CTkEntry(frame, show="*", placeholder_text="Confirm new password", width=280, height=35)
    confirm_entry.pack(pady=5)

    # Add strength meter label
    strength_label = ctk.CTkLabel(frame, text="", font=("Arial", 12))
    strength_label.pack(pady=(0, 5))

    def update_strength_meter(event=None):
        pwd = new_entry.get()
        strength_text, strength_color = show_password_strength(pwd)
        strength_label.configure(text=strength_text, text_color=strength_color)

    new_entry.bind("<KeyRelease>", update_strength_meter)

    msg_label = ctk.CTkLabel(frame, text="")
    msg_label.pack(pady=5)

    def apply_change():
        result = change_master_password(old_entry.get(), new_entry.get(), confirm_entry.get())
        msg_label.configure(text=result)
        if "✅" in result:
            messagebox.showinfo("Success", "Master password changed successfully!")
            show_login_screen()

    ctk.CTkButton(frame, text="Change", width=200, command=apply_change).pack(pady=10)
    ctk.CTkButton(frame, text="⬅ Back", width=200, fg_color="gray", command=show_dashboard).pack(pady=5)


# ---------- FORGOT PASSWORD ----------
def forgot_password_ui():
    for widget in app.winfo_children():
        widget.destroy()

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=60, pady=80, fill="both", expand=True)

    ctk.CTkLabel(frame, text="⚠️ Reset Master Password", font=("Arial", 22, "bold")).pack(pady=(20, 5))
    ctk.CTkLabel(
        frame,
        text="This will permanently DELETE all stored passwords.\n"
             "To confirm, type DELETE below and press Reset.",
        font=("Arial", 14),
        text_color="orange"
    ).pack(pady=(0, 20))

    confirm_entry = ctk.CTkEntry(frame, placeholder_text="Type DELETE to confirm", width=280, height=40)
    confirm_entry.pack(pady=10)

    def confirm_reset():
        text = confirm_entry.get().strip().upper()
        if text == "DELETE":
            if os.path.exists("master.key"):
                os.remove("master.key")
            if os.path.exists("data.json"):
                os.remove("data.json")
            messagebox.showinfo("Reset Complete", "All data has been erased.\nPlease set a new master password.")
            show_set_master_ui()
        else:
            messagebox.showwarning("Cancelled", "Incorrect confirmation. Type DELETE to proceed.")

    ctk.CTkButton(frame, text="Reset Everything", fg_color="red", width=200, height=40, command=confirm_reset).pack(pady=10)
    ctk.CTkButton(frame, text="⬅ Back to Login", fg_color="gray", width=200, height=35, command=show_login_screen).pack(pady=5)



# ---------- LOGOUT ----------
def logout_user():
    session.current_master_password = None
    show_login_screen()



# ---------- AUTO BACKUP ----------
auto_backup_var = ctk.BooleanVar(value=False)

def start_auto_backup():
    """Run auto backup once per day if enabled."""
    if auto_backup_var.get():
        threading.Thread(target=auto_backup, daemon=True).start()
    app.after(86400000, start_auto_backup)  # 86400000 ms = 24 hours
start_auto_backup()


# ---------- SESSION TIMEOUT CHECK ----------
def start_session_monitor():
    """Check every 5 seconds if session expired."""
    if session.is_session_expired():
        session.logout()
        messagebox.showwarning("Session Expired", "You were logged out due to inactivity.")
        show_login_screen()
    else:
        app.after(5000, start_session_monitor)  # check every 5 sec
# ---------- START ----------
show_login_screen()
app.mainloop()
