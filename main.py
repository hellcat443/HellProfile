import os
import json
import base64
import getpass
import sys
import platform
import pathlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime

class ProfileManager:
    def __init__(self):
        if platform.system() == 'Windows':
            self.base_dir = os.path.join(os.environ['APPDATA'], 'HellProfile')
        else:
            self.base_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'HellProfile')
        
        os.makedirs(self.base_dir, exist_ok=True)
    
    def get_profile_path(self, profile_name):
        return os.path.join(self.base_dir, f"{profile_name}.enc")
    
    def get_profiles_list(self):
        profiles = []
        for file in os.listdir(self.base_dir):
            if file.endswith('.enc'):
                profiles.append(file[:-4])
        return profiles
    
    def profile_exists(self, profile_name):
        return os.path.exists(self.get_profile_path(profile_name))
    
    def create_profile_metadata(self, profile_name, description=""):
        metadata_path = os.path.join(self.base_dir, 'profiles_metadata.json')
        
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            except:
                metadata = {}
        else:
            metadata = {}
        
        metadata[profile_name] = {
            'description': description,
            'created_at': self.get_current_datetime(),
            'last_accessed': self.get_current_datetime()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
    
    def update_last_accessed(self, profile_name):
        metadata_path = os.path.join(self.base_dir, 'profiles_metadata.json')
        
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if profile_name in metadata:
                    metadata[profile_name]['last_accessed'] = self.get_current_datetime()
                    
                    with open(metadata_path, 'w') as f:
                        json.dump(metadata, f)
            except:
                pass
    
    def get_profile_metadata(self, profile_name=None):
        metadata_path = os.path.join(self.base_dir, 'profiles_metadata.json')
        
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if profile_name:
                    return metadata.get(profile_name, {})
                return metadata
            except:
                return {} if profile_name else {}
        return {} if profile_name else {}
    
    def get_current_datetime(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class PasswordManager:
    def __init__(self, profile_name="default"):
        self.profile_manager = ProfileManager()
        self.profile_name = profile_name
        self.file_path = self.profile_manager.get_profile_path(profile_name)
        self.master_password = None
        self.entries = {}
        self.key = None
        
    def generate_key(self, password):
        password = password.encode()
        salt = b'secure_salt_value'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def set_master_password(self, password):
        self.master_password = password
        self.key = self.generate_key(password)
        return self.key
    
    def switch_profile(self, profile_name):
        self.profile_name = profile_name
        self.file_path = self.profile_manager.get_profile_path(profile_name)
        self.entries = {}
        self.key = None
        self.master_password = None
        
        self.profile_manager.update_last_accessed(profile_name)
    
    def create_new_vault(self, password, description=""):
        self.set_master_password(password)
        self.entries = {}
        self.save_vault()
        self.profile_manager.create_profile_metadata(self.profile_name, description)
        return True
    
    def load_vault(self, password):
        if not os.path.exists(self.file_path):
            return False
        
        key = self.generate_key(password)
        fernet = Fernet(key)
        
        try:
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = fernet.decrypt(encrypted_data)
                self.entries = json.loads(decrypted_data.decode())
            
            self.set_master_password(password)
            self.profile_manager.update_last_accessed(self.profile_name)
            return True
        except Exception as e:
            print(f"Error loading vault: {e}")
            return False
    
    def save_vault(self):
        if not self.key:
            return False
        
        fernet = Fernet(self.key)
        encrypted_data = fernet.encrypt(json.dumps(self.entries).encode())
        
        with open(self.file_path, 'wb') as file:
            file.write(encrypted_data)
        return True
    
    def add_entry(self, name, website=None, username=None, password=None, is_note=False, note_content=None):
        if is_note:
            self.entries[name] = {
                'type': 'note',
                'title': website or '',
                'content': note_content or ''
            }
        else:
            self.entries[name] = {
                'type': 'password',
                'website': website or '',
                'username': username or '',
                'password': password or ''
            }
        self.save_vault()
    
    def get_entry(self, name):
        return self.entries.get(name)
    
    def remove_entry(self, name):
        if name in self.entries:
            del self.entries[name]
            self.save_vault()
            return True
        return False
    
    def get_all_entries(self):
        return self.entries


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HellProfile by hellcat443")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        self.profile_manager = ProfileManager()
        self.password_manager = PasswordManager()
        self.current_profile = None
        
        self.setup_styles()
        
        profiles = self.profile_manager.get_profiles_list()
        if profiles:
            self.setup_profile_selection_screen()
        else:
            self.setup_create_profile_screen()
    
    def center_window(self, window, width, height):
        self.root.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()
        x = root_x + (root_width // 2) - (width // 2)
        y = root_y + (root_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_styles(self):
        style = ttk.Style()
        style.configure('TButton', font=('Arial', 10))
        style.configure('TLabel', font=('Arial', 10))
        style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Profile.TFrame', padding=10, relief='solid', borderwidth=1)
    
    def setup_profile_selection_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Select Profile", style='Header.TLabel').pack(pady=10)
        
        profiles_frame = ttk.Frame(frame)
        profiles_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        canvas = tk.Canvas(profiles_frame)
        scrollbar = ttk.Scrollbar(profiles_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        profiles = self.profile_manager.get_profiles_list()
        metadata = self.profile_manager.get_profile_metadata()
        
        for i, profile in enumerate(profiles):
            profile_frame = ttk.Frame(scrollable_frame, style='Profile.TFrame')
            profile_frame.pack(fill=tk.X, pady=5, padx=5)
            
            profile_info = metadata.get(profile, {})
            description = profile_info.get('description', 'No description')
            last_accessed = profile_info.get('last_accessed', 'Never')
            
            ttk.Label(profile_frame, text=profile, font=('Arial', 12, 'bold')).grid(row=0, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(profile_frame, text=f"Description: {description}").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(profile_frame, text=f"Last accessed: {last_accessed}").grid(row=2, column=0, sticky="w", padx=5, pady=2)
            
            ttk.Button(profile_frame, text="Open", 
                       command=lambda p=profile: self.open_profile(p)).grid(row=1, column=1, padx=5, pady=5, rowspan=2)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Create New Profile", 
                   command=self.setup_create_profile_screen).pack(side=tk.LEFT, padx=5)
    
    def setup_create_profile_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Create New Profile", style='Header.TLabel').pack(pady=10)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Profile Name:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.profile_name_entry = ttk.Entry(form_frame, width=30)
        self.profile_name_entry.grid(row=0, column=1, padx=5, pady=5)
        self.profile_name_entry.focus()
        
        ttk.Label(form_frame, text="Description (optional):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.profile_desc_entry = ttk.Entry(form_frame, width=30)
        self.profile_desc_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Master Password:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.master_password_entry = ttk.Entry(form_frame, show="*", width=30)
        self.master_password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Confirm Password:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.confirm_password_entry = ttk.Entry(form_frame, show="*", width=30)
        self.confirm_password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Create Profile", 
                   command=self.create_profile).pack(side=tk.LEFT, padx=5)
        
        if self.profile_manager.get_profiles_list():
            ttk.Button(button_frame, text="Back to Profile Selection", 
                      command=self.setup_profile_selection_screen).pack(side=tk.LEFT, padx=5)
    
    def create_profile(self):
        profile_name = self.profile_name_entry.get()
        description = self.profile_desc_entry.get()
        password = self.master_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not profile_name:
            messagebox.showerror("Error", "Please enter a profile name")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if self.profile_manager.profile_exists(profile_name):
            messagebox.showerror("Error", f"A profile named '{profile_name}' already exists")
            return
        
        self.password_manager.switch_profile(profile_name)
        success = self.password_manager.create_new_vault(password, description)
        
        if success:
            messagebox.showinfo("Success", f"Profile '{profile_name}' created successfully")
            self.current_profile = profile_name
            self.setup_main_screen()
        else:
            messagebox.showerror("Error", "Failed to create profile")
    
    def open_profile(self, profile_name):
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Open Profile: {profile_name}")
        self.center_window(dialog, 400, 150)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Enter master password for profile '{profile_name}':", 
                 wraplength=350).pack(pady=10, padx=20)
        
        password_entry = ttk.Entry(dialog, show="*", width=30)
        password_entry.pack(pady=10, padx=20)
        password_entry.focus()
        
        def try_open_profile():
            password = password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter password", parent=dialog)
                return
            
            self.password_manager.switch_profile(profile_name)
            success = self.password_manager.load_vault(password)
            
            if success:
                self.current_profile = profile_name
                dialog.destroy()
                self.setup_main_screen()
            else:
                messagebox.showerror("Error", "Invalid password or vault corrupted", parent=dialog)
        
        ttk.Button(dialog, text="Open", command=try_open_profile).pack(pady=10)
        
        dialog.bind('<Return>', lambda event: try_open_profile())
    
    def setup_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.root.title(f"Password Manager - Profile: {self.current_profile}")
        
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        profile_info_frame = ttk.Frame(main_frame)
        profile_info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(profile_info_frame, text=f"Current Profile: {self.current_profile}", 
                 font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(profile_info_frame, text="Switch Profile", 
                  command=self.setup_profile_selection_screen).pack(side=tk.RIGHT, padx=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Add Password", 
                  command=self.add_entry_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add Note", 
                  command=self.add_note_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Entry", 
                  command=self.remove_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Details", 
                  command=self.view_entry_details).pack(side=tk.LEFT, padx=5)
        
        columns = ('name', 'type', 'info')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings')
        
        self.tree.heading('name', text='Name')
        self.tree.heading('type', text='Type')
        self.tree.heading('info', text='Information')
        
        self.tree.column('name', width=150)
        self.tree.column('type', width=100)
        self.tree.column('info', width=250)
        
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text=f"User: {self.current_profile}").pack(side=tk.LEFT, padx=5)
        ttk.Label(status_frame, text=f"Date: {self.profile_manager.get_current_datetime()}").pack(side=tk.RIGHT, padx=5)
        
        self.load_entries()
        
        self.setup_context_menu()
    
    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_entry_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Website", command=self.copy_website)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Entry", command=self.remove_entry)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_website(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        item_values = self.tree.item(selected_item, 'values')
        name = item_values[0]
        entry_type = item_values[1]
        
        if entry_type != "Password":
            messagebox.showinfo("Information", "Selected entry does not have a website")
            return
        
        entry = self.password_manager.get_entry(name)
        if entry and 'website' in entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(entry['website'])
            messagebox.showinfo("Copy", "Website copied to clipboard")
    
    def copy_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        item_values = self.tree.item(selected_item, 'values')
        name = item_values[0]
        entry_type = item_values[1]
        
        if entry_type != "Password":
            messagebox.showinfo("Information", "Selected entry does not have a password")
            return
        
        entry = self.password_manager.get_entry(name)
        if entry and 'password' in entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(entry['password'])
            messagebox.showinfo("Copy", "Password copied to clipboard")
    
    def copy_username(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        item_values = self.tree.item(selected_item, 'values')
        name = item_values[0]
        entry_type = item_values[1]
        
        if entry_type != "Password":
            messagebox.showinfo("Information", "Selected entry does not have a username")
            return
        
        entry = self.password_manager.get_entry(name)
        if entry and 'username' in entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(entry['username'])
            messagebox.showinfo("Copy", "Username copied to clipboard")
    
    def load_entries(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        entries = self.password_manager.get_all_entries()
        for name, data in entries.items():
            if data.get('type') == 'note':
                self.tree.insert('', tk.END, values=(name, "Note", data.get('title', '')))
            else:
                self.tree.insert('', tk.END, values=(name, "Password", 
                                                   f"Site: {data.get('website', '')}, User: {data.get('username', '')}"))
    
    def add_entry_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        self.center_window(dialog, 400, 200)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        name_entry.focus()
        
        ttk.Label(dialog, text="Website:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        website_entry = ttk.Entry(dialog, width=30)
        website_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Username:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        password_entry = ttk.Entry(dialog, show="*", width=30)
        password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        def save_entry():
            name = name_entry.get()
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            
            if not name or not password:
                messagebox.showerror("Error", "Name and password are required", parent=dialog)
                return
            
            self.password_manager.add_entry(name, website, username, password)
            self.load_entries()
            dialog.destroy()
        
        ttk.Button(dialog, text="Save", command=save_entry).grid(row=4, column=0, columnspan=2, pady=10)
        
        dialog.bind('<Return>', lambda event: save_entry())
    
    def add_note_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Note")
        self.center_window(dialog, 450, 300)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        name_entry.focus()
        
        ttk.Label(dialog, text="Title:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        title_entry = ttk.Entry(dialog, width=30)
        title_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Content:").grid(row=2, column=0, padx=5, pady=5, sticky="nw")
        content_text = tk.Text(dialog, width=30, height=10)
        content_text.grid(row=2, column=1, padx=5, pady=5)
        
        def save_note():
            name = name_entry.get()
            title = title_entry.get()
            content = content_text.get("1.0", tk.END).strip()
            
            if not name:
                messagebox.showerror("Error", "Name is required", parent=dialog)
                return
            
            self.password_manager.add_entry(name, title, is_note=True, note_content=content)
            self.load_entries()
            dialog.destroy()
        
        ttk.Button(dialog, text="Save", command=save_note).grid(row=3, column=0, columnspan=2, pady=10)
    
    def remove_entry(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Select an entry to delete")
            return
        
        item_values = self.tree.item(selected_item, 'values')
        name = item_values[0]
        
        confirm_dialog = tk.Toplevel(self.root)
        confirm_dialog.title("Confirm Deletion")
        self.center_window(confirm_dialog, 350, 150)
        confirm_dialog.resizable(False, False)
        confirm_dialog.transient(self.root)
        confirm_dialog.grab_set()
        
        ttk.Label(confirm_dialog, text=f"Are you sure you want to delete '{name}'?", 
                 wraplength=300).pack(pady=15, padx=20)
        
        button_frame = ttk.Frame(confirm_dialog)
        button_frame.pack(pady=10)
        
        def confirm_delete():
            self.password_manager.remove_entry(name)
            self.load_entries()
            confirm_dialog.destroy()
        
        ttk.Button(button_frame, text="Yes", command=confirm_delete).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="No", command=confirm_dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def view_entry_details(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Select an entry to view")
            return
        
        item_values = self.tree.item(selected_item, 'values')
        name = item_values[0]
        entry_type = item_values[1]
        
        entry = self.password_manager.get_entry(name)
        if entry:
            details_dialog = tk.Toplevel(self.root)
            details_dialog.title(f"Details: {name}")
            
            if entry_type == "Note":
                self.center_window(details_dialog, 500, 300)
                details_dialog.resizable(True, True)
                
                ttk.Label(details_dialog, text=f"Name: {name}", font=('Arial', 12, 'bold')).pack(anchor="w", padx=20, pady=5)
                ttk.Label(details_dialog, text=f"Title: {entry.get('title', '')}").pack(anchor="w", padx=20, pady=5)
                
                content_frame = ttk.Frame(details_dialog)
                content_frame.pack(fill="both", expand=True, padx=20, pady=5)
                
                ttk.Label(content_frame, text="Content:").pack(anchor="w")
                
                text_frame = ttk.Frame(content_frame)
                text_frame.pack(fill="both", expand=True, pady=5)
                
                content_text = tk.Text(text_frame, wrap="word", height=10)
                content_text.pack(side="left", fill="both", expand=True)
                content_text.insert("1.0", entry.get('content', ''))
                content_text.config(state="disabled")
                
                scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=content_text.yview)
                content_text.configure(yscrollcommand=scrollbar.set)
                scrollbar.pack(side="right", fill="y")
                
                copy_button = ttk.Button(details_dialog, text="Copy Content", 
                                       command=lambda: [self.root.clipboard_clear(), 
                                                      self.root.clipboard_append(entry.get('content', '')), 
                                                      messagebox.showinfo("Copy", "Content copied", parent=details_dialog)])
                copy_button.pack(pady=5)
                
            else:
                self.center_window(details_dialog, 400, 250)
                details_dialog.resizable(False, False)
                
                ttk.Label(details_dialog, text=f"Name: {name}", font=('Arial', 12, 'bold')).pack(anchor="w", padx=20, pady=5)
                
                website_frame = ttk.Frame(details_dialog)
                website_frame.pack(anchor="w", padx=20, pady=5, fill="x")
                ttk.Label(website_frame, text=f"Website: {entry.get('website', '')}").pack(side=tk.LEFT)
                ttk.Button(website_frame, text="Copy", 
                          command=lambda: [self.root.clipboard_clear(), 
                                          self.root.clipboard_append(entry.get('website', '')), 
                                          messagebox.showinfo("Copy", "Website copied", parent=details_dialog)]).pack(side=tk.RIGHT, padx=10)
                
                username_frame = ttk.Frame(details_dialog)
                username_frame.pack(anchor="w", padx=20, pady=5, fill="x")
                ttk.Label(username_frame, text=f"Username: {entry.get('username', '')}").pack(side=tk.LEFT)
                ttk.Button(username_frame, text="Copy", 
                          command=lambda: [self.root.clipboard_clear(), 
                                          self.root.clipboard_append(entry.get('username', '')), 
                                          messagebox.showinfo("Copy", "Username copied", parent=details_dialog)]).pack(side=tk.RIGHT, padx=10)
                
                password_frame = ttk.Frame(details_dialog)
                password_frame.pack(anchor="w", padx=20, pady=5, fill="x")
                ttk.Label(password_frame, text=f"Password: {entry.get('password', '')}").pack(side=tk.LEFT)
                ttk.Button(password_frame, text="Copy", 
                          command=lambda: [self.root.clipboard_clear(), 
                                          self.root.clipboard_append(entry.get('password', '')), 
                                          messagebox.showinfo("Copy", "Password copied", parent=details_dialog)]).pack(side=tk.RIGHT, padx=10)
            
            details_dialog.transient(self.root)
            details_dialog.grab_set()
            ttk.Button(details_dialog, text="Close", command=details_dialog.destroy).pack(pady=15)


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
