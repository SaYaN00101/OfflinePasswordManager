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
    frame.pack(padx=60, pady=60, fill="both", expand=True)

    # Header / Logo
    header = ctk.CTkFrame(frame, fg_color="transparent")
    header.pack(pady=(10, 8))
    ctk.CTkLabel(header, text="🔐 Offline Password Manager", font=("Arial", 22, "bold")).pack()
    ctk.CTkLabel(header, text="Enter your master password to unlock your vault", font=("Arial", 12), text_color="gray").pack()

    # Entry area
    content = ctk.CTkFrame(frame, fg_color="transparent")
    content.pack(pady=(10, 10))

    password_entry = ctk.CTkEntry(content, show="*", width=320, height=40, placeholder_text="Master Password")
    password_entry.grid(row=0, column=0, columnspan=2, pady=(6, 4))
    password_entry.focus()

    show_pwd_var = ctk.BooleanVar(value=False)
    def toggle_show_pwd():
        password_entry.configure(show="" if show_pwd_var.get() else "*")
    ctk.CTkCheckBox(content, text="Show password", variable=show_pwd_var, command=toggle_show_pwd).grid(row=1, column=0, sticky="w", padx=(8,0))

    remember_var = ctk.BooleanVar(value=False)
    ctk.CTkCheckBox(content, text="Remember session", variable=remember_var).grid(row=1, column=1, sticky="e", padx=(0,8))

    error_label = ctk.CTkLabel(frame, text="", text_color="red")
    error_label.pack(pady=(6, 4))

    # Convenience: press Enter to submit
    password_entry.bind("<Return>", lambda e: check_login())

    def check_login():
        entered_password = password_entry.get().strip()
        if not entered_password:
            error_label.configure(text="❌ Please enter your password")
            return

        result = verify_master_password(entered_password)

        if result is True:
            session.current_master_password = entered_password  # store globally in session
            # mark activity now that the user has logged in so the timeout doesn't trigger immediately
            try:
                session.update_activity()
            except Exception:
                pass
            # extend session if user asked to remember (keep it alive longer)
            if remember_var.get():
                session.extend_session = True if hasattr(session, "extend_session") else None
            show_dashboard()
            start_session_monitor()

        elif result is None:
            messagebox.showinfo("Setup", "No master password found. Please create one.")
            show_set_master_ui()
        else:
            error_label.configure(text="❌ Incorrect password!")
            # keep focus on entry for quick retry
            password_entry.focus()
            password_entry.select_range(0, "end")

    # Buttons
    btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
    btn_frame.pack(pady=(6, 4))

    ctk.CTkButton(btn_frame, text="Login", width=200, height=40, command=check_login).grid(row=0, column=0, padx=6, pady=6)
    # Only show "Set Master Password" if master.key doesn't exist
    if not os.path.exists("master.key"):
        ctk.CTkButton(btn_frame, text="Set Master Password", width=200, command=show_set_master_ui).grid(row=1, column=0, padx=6, pady=4)
    ctk.CTkButton(btn_frame, text="Forgot Password?", fg_color="gray", width=200, command=forgot_password_ui).grid(row=2, column=0, padx=6, pady=4)


def show_set_master_ui():
    for widget in app.winfo_children():
        widget.destroy()

    from utils import show_password_strength

    frame = ctk.CTkFrame(app, corner_radius=20)
    frame.pack(padx=40, pady=40, fill="both", expand=True)

    # Title
    ctk.CTkLabel(frame, text="🛡️ Set Master Password", font=("Arial", 22, "bold")).pack(pady=(8, 4))
    ctk.CTkLabel(frame, text="Choose a strong master password. You will not be able to recover it.", font=("Arial", 12), text_color="gray").pack(pady=(0, 8))

    # Warning (animated color)
    warning_label = ctk.CTkLabel(
        frame,
        text="⚠️ Warning: If you forget this password, all stored data will be unrecoverable!",
        font=("Arial", 12, "italic"),
        text_color=("gray70", "gray70")
    )
    warning_label.pack(pady=(4, 8))

    def fade_in(step=0):
        colors = ["gray70", "gray60", "gray50", "gray40", "orange3", "orange2", "orange"]
        if step < len(colors):
            warning_label.configure(text_color=colors[step])
            frame.after(120, fade_in, step + 1)
    fade_in()

    # Strength meter area
    strength_label = ctk.CTkLabel(frame, text="", font=("Arial", 12))
    strength_label.pack(pady=(6, 4))
    strength_bar = ctk.CTkProgressBar(frame, width=320)
    strength_bar.pack(pady=(0, 8))

    # Password fields
    inputs = ctk.CTkFrame(frame, fg_color="transparent")
    inputs.pack(pady=(4, 8))

    password_entry = ctk.CTkEntry(inputs, show="*", width=320, height=40, placeholder_text="Enter new master password")
    password_entry.grid(row=0, column=0, columnspan=2, pady=(4, 6))
    password_entry.focus()

    confirm_entry = ctk.CTkEntry(inputs, show="*", width=320, height=40, placeholder_text="Confirm master password")
    confirm_entry.grid(row=1, column=0, columnspan=2, pady=(4, 6))

    show_pwd_var = ctk.BooleanVar(value=False)
    def toggle_show():
        s = "" if show_pwd_var.get() else "*"
        password_entry.configure(show=s)
        confirm_entry.configure(show=s)
    ctk.CTkCheckBox(inputs, text="Show passwords", variable=show_pwd_var, command=toggle_show).grid(row=2, column=0, sticky="w", padx=(4,0))


    message_label = ctk.CTkLabel(frame, text="", text_color="lightgray")
    message_label.pack(pady=(6, 4))

    # Validate inputs and update strength UI
    def password_score(pwd: str):
        has_len = len(pwd) >= 12
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_symbol = any(not c.isalnum() for c in pwd)
        score = sum([has_len, has_upper, has_lower, has_digit, has_symbol])
        return {
            "has_len": has_len,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "score": score
        }

    def update_strength(event=None):
        pwd = password_entry.get()
        info = password_score(pwd)
        # Requirements UI removed — update strength display only

        # use utils function for a friendly label if available
        try:
            friendly, color = show_password_strength(pwd)
            strength_label.configure(text=friendly, text_color=color)
        except Exception:
            # fallback
            strength_label.configure(text=f"Strength: {info['score']}/5", text_color="gray")

        strength_bar.set(info["score"] / 5 if info["score"] > 0 else 0)
        # color progress bar if supported
        try:
            if info["score"] <= 2:
                strength_bar.configure(progress_color="red")
            elif info["score"] == 3:
                strength_bar.configure(progress_color="orange")
            else:
                strength_bar.configure(progress_color="green")
        except Exception:
            pass

        # Enable/disable set button depending on rules and match
        pw = password_entry.get()
        match = pw and (pw == confirm_entry.get())
        requirements_ok = info["score"] >= 4  # require at least 4/5
        if requirements_ok and match:
            set_btn.configure(state="normal")
            message_label.configure(text="")
        else:
            set_btn.configure(state="disabled")
            if not match and confirm_entry.get():
                message_label.configure(text="⚠️ Passwords do not match")
            else:
                message_label.configure(text="")

    password_entry.bind("<KeyRelease>", update_strength)
    confirm_entry.bind("<KeyRelease>", update_strength)
    password_entry.bind("<Return>", lambda e: confirm_entry.focus())
    confirm_entry.bind("<Return>", lambda e: set_password())

    # Action
    def set_password():
        pwd = password_entry.get()
        confirm = confirm_entry.get()
        if not pwd or not confirm:
            message_label.configure(text="❌ Fill both fields")
            return
        # Call existing UI-level setter which returns a status string
        result = set_master_password_ui(pwd, confirm)
        message_label.configure(text=result)
        if "✅" in result:
            messagebox.showinfo("Success", "Master password set successfully!")
            show_login_screen()

    # Buttons
    btns = ctk.CTkFrame(frame, fg_color="transparent")
    btns.pack(pady=(6, 6))
    
    set_btn = ctk.CTkButton(btns, text="Set Password", width=200, height=40, command=set_password, state="disabled")
    set_btn.pack(pady=6)
    
    back_btn = ctk.CTkButton(btns, text="⬅ Back to Login", fg_color="gray", width=200, height=36, command=show_login_screen)
    back_btn.pack(pady=6)

    # initial update to reflect empty state
    update_strength()

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
