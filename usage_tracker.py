import psutil
import time
from datetime import datetime
import pandas as pd
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

# Globals
log_file = "log.csv"
tracked_apps = []
tracking = False

# Initialize log file
def initialize_log():
    try:
        with open(log_file, 'x') as file:
            file.write("Process,Start Time,End Time,Usage Time (min)\n")
    except FileExistsError:
        pass

# Log app usage to file
def log_usage(app_name, start_time, end_time):
    duration = (end_time - start_time).total_seconds() / 60
    with open(log_file, "a") as file:
        file.write(f"{app_name},{start_time},{end_time},{duration:.2f}\n")
    
    # Temporarily enable the log display widget for inserting log content
    log_display.config(state=tk.NORMAL)
    log_display.insert(tk.END, f"Logged: {app_name}, Duration: {duration:.2f} min\n")
    log_display.see(tk.END)  # Scroll to the bottom
    log_display.config(state=tk.DISABLED)

# Track selected apps
def track_apps():
    active_apps = {}
    while tracking:
        running_apps = {p.info['name']: p for p in psutil.process_iter(['name'])}
        for app in tracked_apps:
            if app in running_apps and app not in active_apps:
                active_apps[app] = datetime.now()
                # Temporarily enable the log display widget for inserting "Started tracking" message
                log_display.config(state=tk.NORMAL)
                log_display.insert(tk.END, f"Started tracking: {app}\n")
                log_display.see(tk.END)
                log_display.config(state=tk.DISABLED)
        for app, start_time in list(active_apps.items()):
            if app not in running_apps:
                end_time = datetime.now()
                log_usage(app, start_time, end_time)
                active_apps.pop(app)
        time.sleep(5)

    # Check for still running apps after tracking is stopped
    running_apps = {p.info['name']: p for p in psutil.process_iter(['name'])}
    for app in tracked_apps:
        if app in running_apps:
            # Temporarily enable the log display widget for inserting "Still running" message
            log_display.config(state=tk.NORMAL)
            log_display.insert(tk.END, f"{app} is still running, but tracking has stopped.\n")
            log_display.see(tk.END)
            log_display.config(state=tk.DISABLED)

# Toggle tracking state
def toggle_tracking():
    global tracking
    tracking = not tracking
    tracking_button.config(text="Stop Tracking" if tracking else "Start Tracking")
    if tracking:
        if not tracked_apps:
            messagebox.showwarning("Warning", "No apps selected for tracking.")
            tracking = False
            return
        threading.Thread(target=track_apps, daemon=True).start()
        process_listbox.config(state=tk.DISABLED)
    else:
        process_listbox.config(state=tk.NORMAL)
        create_report()

# Generate report
def create_report():
    try:
        df = pd.read_csv(log_file)
        if df.empty:
            report_text.config(state=tk.NORMAL)
            report_text.delete(1.0, tk.END)
            report_text.insert(tk.END, "No data available.\n")
            report_text.config(state=tk.DISABLED)
            return
        summary = df.groupby("Process")["Usage Time (min)"].sum().reset_index()
        summary["Usage Time (min)"] = summary["Usage Time (min)"].apply(lambda x: f"{x:.2f} min")
        
        # Temporarily enable the report text widget for inserting the summary
        report_text.config(state=tk.NORMAL)
        report_text.delete(1.0, tk.END)
        report_text.insert(tk.END, "Usage Summary (in minutes):\n")
        report_text.insert(tk.END, print_dataframe(summary))  # Use print_dataframe to format
        report_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Error creating report: {e}")

# Function to format the DataFrame into a text table with aligned columns
def print_dataframe(df):
    # Calculate max widths for each column to align them properly
    max_widths = {col: max(df[col].astype(str).map(len).max(), len(col)) for col in df.columns}
    
    # Create the header with column names aligned
    header = " | ".join(f"{col:^{max_widths[col]}}" for col in df.columns)
    output = header + "\n" + "-" * len(header) + "\n"  # Add a separator line
    
    # Create each row in the table, aligning values
    for _, row in df.iterrows():
        row_str = " | ".join(f"{str(value):^{max_widths[col]}}" for col, value in zip(df.columns, row))
        output += row_str + "\n"
    
    return output

# Update selected apps
def update_tracked_apps(event=None):
    global tracked_apps
    selected = process_listbox.curselection()
    tracked_apps = [process_listbox.get(i) for i in selected]
    selected_processes_label.config(state=tk.NORMAL)
    selected_processes_label.delete(1.0, tk.END)
    selected_processes_label.insert(tk.END, f"Tracking: {', '.join(tracked_apps)}" if tracked_apps else "No processes selected")
    selected_processes_label.config(state=tk.DISABLED)
    tracking_button.config(state=tk.NORMAL if tracked_apps else tk.DISABLED)

# Refresh process list
def refresh_process_list():
    if tracking:
        return  # Prevent refresh if tracking is active

    process_listbox.delete(0, tk.END)
    for process in sorted(set(p.info['name'] for p in psutil.process_iter(['name']))):
        process_listbox.insert(tk.END, process)
    
    # Clear the selected processes display
    selected_processes_label.config(state=tk.NORMAL)
    selected_processes_label.delete(1.0, tk.END)
    selected_processes_label.insert(tk.END, "No processes selected")
    selected_processes_label.config(state=tk.DISABLED)

# Clear logs and reset
def clear_all():
    log_display.config(state=tk.NORMAL)
    log_display.delete(1.0, tk.END)
    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    with open(log_file, 'w') as file:
        file.write("Process,Start Time,End Time,Usage Time (min)\n")
    messagebox.showinfo("Info", "Logs cleared.")
    log_display.config(state=tk.DISABLED)
    report_text.config(state=tk.DISABLED)

# Filter process list
def filter_processes(event):
    search_term = search_entry.get().lower()
    process_listbox.delete(0, tk.END)
    for process in sorted(set(p.info['name'] for p in psutil.process_iter(['name']))):
        if search_term in process.lower():
            process_listbox.insert(tk.END, process)

# Build GUI
root = tk.Tk()
root.title("App Usage Tracker")
root.geometry("1350x600")

# Left panel
left_frame = tk.Frame(root)
left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

tracking_button = tk.Button(left_frame, text="Start Tracking", command=toggle_tracking, state=tk.DISABLED)
tracking_button.pack(pady=10)

search_frame = tk.Frame(left_frame)
search_frame.pack()
tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame, width=30)
search_entry.pack(side=tk.LEFT)
search_entry.bind("<KeyRelease>", filter_processes)

process_listbox = tk.Listbox(left_frame, selectmode=tk.MULTIPLE, width=50, height=15, exportselection=False)
process_listbox.pack(pady=10)
process_listbox.bind('<<ListboxSelect>>', update_tracked_apps)

button_frame = tk.Frame(left_frame)
button_frame.pack()
tk.Button(button_frame, text="Refresh List", command=refresh_process_list).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Clear All Logs", command=clear_all).pack(side=tk.LEFT, padx=5)

selected_processes_label = tk.Text(left_frame, width=50, height=5, wrap=tk.WORD, bg=root.cget("bg"), borderwidth=1, relief="solid")
selected_processes_label.pack(pady=10)
selected_processes_label.config(state=tk.DISABLED)

# Right panel
right_frame = tk.Frame(root)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

log_display = scrolledtext.ScrolledText(right_frame, height=15, borderwidth=1, relief="solid")
log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
log_display.config(state=tk.DISABLED)  # Make log display read-only

report_text = scrolledtext.ScrolledText(right_frame, height=15, borderwidth=1, relief="solid")
report_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
report_text.config(state=tk.DISABLED)  # Make report text read-only

# Initialize and start
initialize_log()
refresh_process_list()
root.mainloop()
