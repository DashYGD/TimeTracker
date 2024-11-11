import psutil
import time
from datetime import datetime
import pandas as pd
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

log_file = "log.csv"
tracked_apps = []
tracking = False

def initialize_log():
    try:
        with open(log_file, 'x') as file:
            file.write("Process,Start Time,End Time,Usage Time (min)\n")
    except FileExistsError:
        pass

def log_usage(app_name, start_time, end_time):
    usage_duration = (end_time - start_time).total_seconds() / 60
    with open(log_file, "a") as file:
        file.write(f"{app_name},{start_time},{end_time},{usage_duration:.2f}\n")
    log_display.insert(tk.END, f"Logged: {app_name}, Duration: {usage_duration:.2f} min\n")
    log_display.see(tk.END)

def track_apps():
    active_apps = {}
    while tracking:
        for process in psutil.process_iter(['name']):
            app_name = process.info['name']
            if app_name in tracked_apps and app_name not in active_apps:
                active_apps[app_name] = datetime.now()
                log_display.insert(tk.END, f"Started tracking: {app_name} at {active_apps[app_name]}\n")
                log_display.see(tk.END)
        for app_name in list(active_apps.keys()):
            if app_name not in [process.info['name'] for process in psutil.process_iter(['name'])]:
                start_time = active_apps.pop(app_name)
                end_time = datetime.now()
                log_usage(app_name, start_time, end_time)
                log_display.insert(tk.END, f"Stopped tracking: {app_name} at {end_time}\n")
                log_display.see(tk.END)
        time.sleep(5)

def toggle_tracking():
    global tracking
    tracking = not tracking
    tracking_button.config(text="Stop Tracking" if tracking else "Start Tracking")
    if tracking:
        if not tracked_apps:
            messagebox.showwarning("Warning", "No processes selected for tracking.")
            tracking = False
            tracking_button.config(text="Start Tracking")
            return
        messagebox.showinfo("Info", "Tracking started...")
        process_listbox.config(state=tk.DISABLED)
        thread = threading.Thread(target=track_apps)
        thread.start()
    else:
        messagebox.showinfo("Info", "Tracking stopped.")
        process_listbox.config(state=tk.NORMAL)
        for app_name in tracked_apps:
            if app_name in [process.info['name'] for process in psutil.process_iter(['name'])]:
                log_display.insert(tk.END, f"{app_name} is still running, but tracking has stopped.\n")
                log_display.see(tk.END)
        create_report()

def create_report():
    try:
        df = pd.read_csv(log_file)
        if df.empty:
            report_text.delete(1.0, tk.END)
            report_text.insert(tk.END, "No enough data to create a report.\n")
            return
        summary = df.groupby("Process")["Usage Time (min)"].sum().reset_index()
        summary.columns = ["Process", "Used Time"]
        summary["Used Time"] = summary["Used Time"].apply(lambda x: f"{x:.2f} min")
        report_text.delete(1.0, tk.END)
        report_text.insert(tk.END, "Usage Summary (in minutes):\n" + print_dataframe(summary))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create report: {e}")

def print_dataframe(df):
    max_widths = {col: max(df[col].astype(str).map(len).max(), len(col)) for col in df.columns}
    header = " | ".join(f"{col:^{max_widths[col]}}" for col in df.columns)
    output = header + "\n" + "-" * len(header) + "\n"
    for _, row in df.iterrows():
        row_str = " | ".join(f"{str(value):^{max_widths[col]}}" for col, value in zip(df.columns, row))
        output += row_str + "\n"
    return output

def update_tracked_apps():
    global tracked_apps
    selected_processes = process_listbox.curselection()
    tracked_apps = [process_listbox.get(i) for i in selected_processes]
    selected_processes_label.config(state=tk.NORMAL)
    selected_processes_label.delete(1.0, tk.END)
    selected_processes_label.insert(tk.END, f"Tracking: {', '.join(tracked_apps)}" if tracked_apps else "No processes selected")
    selected_processes_label.config(state=tk.DISABLED)
    toggle_tracking_button_state()

def toggle_tracking_button_state():
    tracking_button.config(state=tk.NORMAL if tracked_apps else tk.DISABLED)

def clear_selected_processes():
    if tracking:
        messagebox.showwarning("Warning", "Cannot clear selected processes while tracking is active.")
        return
    process_listbox.selection_clear(0, tk.END)
    update_tracked_apps()

def refresh_process_list():
    process_listbox.delete(0, tk.END)
    running_processes = sorted(set(proc.info['name'] for proc in psutil.process_iter(['name'])))
    for process in running_processes:
        process_listbox.insert(tk.END, process)

def filter_processes(event):
    search_term = search_entry.get().lower()
    process_listbox.delete(0, tk.END)
    for process in sorted(set(proc.info['name'] for proc in psutil.process_iter(['name']))):
        if search_term in process.lower():
            process_listbox.insert(tk.END, process)

def clear_all():
    log_display.delete(1.0, tk.END)
    report_text.delete(1.0, tk.END)
    with open(log_file, 'w') as file:
        file.write("Process,Start Time,End Time,Usage Time (min)\n")
    messagebox.showinfo("Info", "All logs and summary cleared.")

root = tk.Tk()
root.title("Usage Tracker")
root.geometry("1350x600")

frame_left = tk.Frame(root)
frame_left.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

tracking_button = tk.Button(frame_left, text="Start Tracking", command=toggle_tracking, state=tk.DISABLED)
tracking_button.pack(pady=10)

search_frame = tk.Frame(frame_left)
search_frame.pack(pady=10)

search_label = tk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT)

search_entry = tk.Entry(search_frame, width=30)
search_entry.pack(side=tk.LEFT)
search_entry.bind("<KeyRelease>", filter_processes)

process_listbox = tk.Listbox(frame_left, selectmode=tk.MULTIPLE, width=50, height=15)
process_listbox.pack(pady=10)
process_listbox.bind('<<ListboxSelect>>', lambda event: update_tracked_apps())

button_frame = tk.Frame(frame_left)
button_frame.pack(pady=10)

clear_button = tk.Button(button_frame, text="Clear Selected", command=clear_selected_processes)
clear_button.pack(side=tk.LEFT, padx=5)

refresh_button = tk.Button(button_frame, text="Refresh Processes", command=refresh_process_list)
refresh_button.pack(side=tk.LEFT, padx=5)

clear_all_button = tk.Button(button_frame, text="Clear All", command=clear_all)
clear_all_button.pack(side=tk.LEFT, padx=5)

selected_processes_label = tk.Text(frame_left, width=60, height=20, wrap=tk.WORD, bg=root.cget("bg"), borderwidth=1, relief="solid")
selected_processes_label.pack(pady=10)
selected_processes_label.config(state=tk.DISABLED)

frame_log_summary = tk.Frame(root)
frame_log_summary.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

log_display = scrolledtext.ScrolledText(frame_log_summary, width=50, height=25, borderwidth=1, relief="solid")
log_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

report_text = scrolledtext.ScrolledText(frame_log_summary, width=50, height=25, borderwidth=1, relief="solid")
report_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

initialize_log()
refresh_process_list()
root.mainloop()
