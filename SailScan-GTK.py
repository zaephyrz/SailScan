#!/usr/bin/env python3
"""
SailScan GTK Desktop App
Run: python SailScan-GTK.py
"""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio
import os
import threading
import subprocess
import webbrowser

class SailScanWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_default_size(900, 700)
        self.set_title("SailScan")
        
        # Create main box
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.set_content(self.main_box)
        
        # Header
        header = Adw.HeaderBar()
        self.main_box.append(header)
        
        # Title
        title_label = Gtk.Label()
        title_label.set_markup("<span size='xx-large' weight='bold'>SailScan 🏴‍☠️</span>\n<span size='small'>Multi-Engine Security Scanner</span>")
        title_label.set_halign(Gtk.Align.START)
        title_label.set_margin_start(20)
        title_label.set_margin_top(20)
        self.main_box.append(title_label)
        
        # Stats Grid
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(20)
        stats_grid.set_row_spacing(10)
        stats_grid.set_margin_start(20)
        stats_grid.set_margin_end(20)
        stats_grid.set_margin_top(20)
        
        # Stats labels
        self.total_label = self.create_stat_label("Total Scans", "0")
        self.threats_label = self.create_stat_label("Threats Found", "0")
        self.status_label = self.create_stat_label("Status", "Ready")
        
        stats_grid.attach(self.total_label, 0, 0, 1, 1)
        stats_grid.attach(self.threats_label, 1, 0, 1, 1)
        stats_grid.attach(self.status_label, 2, 0, 1, 1)
        
        self.main_box.append(stats_grid)
        
        # File Selection
        file_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        file_box.set_margin_start(20)
        file_box.set_margin_end(20)
        file_box.set_margin_top(20)
        
        self.file_label = Gtk.Label(label="No file selected")
        self.file_label.set_hexpand(True)
        
        select_btn = Gtk.Button(label="📁 Select File")
        select_btn.connect("clicked", self.on_select_file)
        
        scan_btn = Gtk.Button(label="🔍 Scan Now")
        scan_btn.add_css_class("suggested-action")
        scan_btn.connect("clicked", self.on_scan_file)
        
        file_box.append(self.file_label)
        file_box.append(select_btn)
        file_box.append(scan_btn)
        
        self.main_box.append(file_box)
        
        # Progress Bar
        self.progress = Gtk.ProgressBar()
        self.progress.set_margin_start(20)
        self.progress.set_margin_end(20)
        self.progress.set_margin_top(10)
        self.progress.set_visible(False)
        self.main_box.append(self.progress)
        
        # Results Area
        self.results_text = Gtk.TextView()
        self.results_text.set_editable(False)
        self.results_text.set_wrap_mode(Gtk.WrapMode.WORD)
        self.results_text.set_margin_start(20)
        self.results_text.set_margin_end(20)
        self.results_text.set_margin_top(20)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.results_text)
        scrolled.set_hexpand(True)
        scrolled.set_vexpand(True)
        self.main_box.append(scrolled)
        
        # Buttons at bottom
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        button_box.set_margin_start(20)
        button_box.set_margin_end(20)
        button_box.set_margin_bottom(20)
        
        web_btn = Gtk.Button(label="🌐 Open Web Version")
        web_btn.connect("clicked", self.open_web_version)
        
        quit_btn = Gtk.Button(label="Quit")
        quit_btn.connect("clicked", lambda btn: self.close())
        
        button_box.append(web_btn)
        button_box.append(quit_btn)
        
        self.main_box.append(button_box)
        
        # Store selected file
        self.selected_file = None
    
    def create_stat_label(self, title, value):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        
        title_label = Gtk.Label(label=title)
        title_label.add_css_class("dim-label")
        
        value_label = Gtk.Label(label=value)
        value_label.add_css_class("title-1")
        
        box.append(title_label)
        box.append(value_label)
        
        return box
    
    def on_select_file(self, button):
        dialog = Gtk.FileDialog()
        dialog.open(self, None, self.on_file_selected)
    
    def on_file_selected(self, dialog, result):
        try:
            file = dialog.open_finish(result)
            if file:
                self.selected_file = file.get_path()
                self.file_label.set_label(f"📄 Selected: {os.path.basename(self.selected_file)}")
        except GLib.Error as error:
            print(f"Error selecting file: {error}")
    
    def on_scan_file(self, button):
        if not self.selected_file:
            self.show_message("Please select a file first", "error")
            return
        
        # Show progress
        self.progress.set_visible(True)
        self.progress.set_fraction(0.1)
        
        # Simulate scan in background
        threading.Thread(target=self.run_scan, daemon=True).start()
    
    def run_scan(self):
        # Simulate scanning
        for i in range(1, 11):
            GLib.idle_add(self.progress.set_fraction, i/10)
            GLib.idle_add(self.status_label.get_last_child().set_label, f"Scanning... {i*10}%")
            import time
            time.sleep(0.3)
        
        # Simulate results
        results = f"""
        🛡️ Scan Results
        =================
        File: {os.path.basename(self.selected_file)}
        Size: {os.path.getsize(self.selected_file)} bytes
        
        🔍 Analysis:
        - File type: {self.get_file_type()}
        - Threat score: 15/100
        - Status: ✅ Clean
        
        📊 Details:
        This file appears safe with low risk indicators.
        No malicious patterns detected.
        
        ℹ️ Note: This is a simulation.
        Enable VirusTotal in web version for real scanning.
        """
        
        GLib.idle_add(self.update_results, results)
        GLib.idle_add(self.progress.set_visible, False)
        GLib.idle_add(self.status_label.get_last_child().set_label, "Completed")
    
    def get_file_type(self):
        ext = os.path.splitext(self.selected_file)[1].lower()
        return {
            '.exe': 'Windows Executable',
            '.dll': 'Windows Library',
            '.apk': 'Android App',
            '.pdf': 'PDF Document',
            '.py': 'Python Script'
        }.get(ext, 'Unknown File Type')
    
    def update_results(self, text):
        buffer = self.results_text.get_buffer()
        buffer.set_text(text)
    
    def show_message(self, message, msg_type="info"):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=message
        )
        dialog.add_response("ok", "OK")
        dialog.present()
    
    def open_web_version(self, button):
        # Start Flask app in background
        threading.Thread(target=self.start_flask_app, daemon=True).start()
        
        # Open browser
        webbrowser.open("http://localhost:5000")
    
    def start_flask_app(self):
        # Start your existing Flask app
        os.chdir("..")  # Go to parent directory where sailscan.py is
        subprocess.run(["python", "sailscan.py"])

class SailScanApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.github.zaephyrz.SailScan")
    
    def do_activate(self):
        win = SailScanWindow(application=self)
        win.present()

def main():
    app = SailScanApp()
    app.run()

if __name__ == "__main__":
    main()