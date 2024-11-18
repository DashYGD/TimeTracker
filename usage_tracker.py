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
tracking_start_time = None
timer_running = False

def initialize_log():
    try:
        with open(log_file, 'x') as file:
            file.write("Process,Start Time,End Time,Usage Time (min)\n")
    except FileExistsError:
        pass

def track_apps():
    active_apps = {}
    while tracking:
        running_apps = {p.info['name']: p for p in psutil.process_iter(['name'])}
        for app in tracked_apps:
            if app in running_apps and app not in active_apps:
                active_apps[app] = datetime.now()
                start_time_str = active_apps[app].strftime("%Y-%m-%d %H:%M:%S")
                log_display.config(state=tk.NORMAL)
                log_display.insert(tk.END, f"Started tracking: {app} at {start_time_str}\n")
                log_display.see(tk.END)
                log_display.config(state=tk.DISABLED)
        for app, start_time in list(active_apps.items()):
            if app not in running_apps:
                end_time = datetime.now()
                log_usage(app, start_time, end_time)
                active_apps.pop(app)
        time.sleep(1)
    for app, start_time in active_apps.items():
        end_time = datetime.now()
        log_usage(app, start_time, end_time)

def update_timer():
    global timer_running
    if not timer_running:
        return
    if tracking_start_time:
        elapsed_time = datetime.now() - tracking_start_time
        hours = elapsed_time.seconds // 3600
        minutes = (elapsed_time.seconds // 60) % 60
        seconds = elapsed_time.seconds % 60
        timer_label.config(text=f"Tracking Time: {hours:02}:{minutes:02}:{seconds:02}")
    root.after(1000, update_timer)

def log_usage(app_name, start_time, end_time):
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration = (end_time - start_time).total_seconds() / 60
    with open(log_file, "a") as file:
        file.write(f"{app_name},{start_time_str},{end_time_str},{duration:.2f}\n")
        file.flush()
    log_display.config(state=tk.NORMAL)
    log_display.insert(tk.END, f"Logged: {app_name}, Duration: {duration:.2f} min\n")
    log_display.see(tk.END)
    log_display.config(state=tk.DISABLED)
    create_report()

def toggle_tracking():
    global tracking, tracking_start_time, timer_running
    tracking = not tracking
    tracking_button.config(text="Stop Tracking" if tracking else "Start Tracking")
    if tracking:
        if not tracked_apps:
            messagebox.showwarning("Warning", "No apps selected for tracking.")
            tracking = False
            return
        tracking_start_time = datetime.now()
        timer_running = True
        update_timer()
        threading.Thread(target=track_apps, daemon=True).start()
        process_listbox.config(state=tk.DISABLED)
    else:
        timer_running = False
        timer_label.config(text="Tracking Time: 0:00:00")
        if tracking_start_time is not None:
            end_time = datetime.now()
            elapsed_time = end_time - tracking_start_time
            hours = elapsed_time.seconds // 3600
            minutes = (elapsed_time.seconds // 60) % 60
            seconds = elapsed_time.seconds % 60
            tracking_time_str = f"{hours:02}:{minutes:02}:{seconds:02}"
            end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            log_display.config(state=tk.NORMAL)
            log_display.insert(tk.END, f"Tracking stopped at {end_time_str}. Total tracking time: {tracking_time_str}. Finalizing logs...\n")
            log_display.see(tk.END)
            log_display.config(state=tk.DISABLED)
            create_report()
        else:
            messagebox.showwarning("Warning", "Tracking has not started yet!")
        process_listbox.config(state=tk.NORMAL)

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
        report_text.config(state=tk.NORMAL)
        report_text.delete(1.0, tk.END)
        report_text.insert(tk.END, "Usage Summary (in minutes):\n")
        report_text.insert(tk.END, print_dataframe(summary))
        report_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Error creating report: {e}")

def print_dataframe(df):
    max_widths = {col: max(df[col].astype(str).map(len).max(), len(col)) for col in df.columns}
    header = " | ".join(f"{col:^{max_widths[col]}}" for col in df.columns)
    output = header + "\n" + "-" * len(header) + "\n"
    for _, row in df.iterrows():
        row_str = " | ".join(f"{str(value):^{max_widths[col]}}" for col, value in zip(df.columns, row))
        output += row_str + "\n"
    return output

def update_tracked_apps(event=None):
    global tracked_apps
    selected = process_listbox.curselection()
    tracked_apps = [process_listbox.get(i) for i in selected]
    selected_processes_label.config(state=tk.NORMAL)
    selected_processes_label.delete(1.0, tk.END)
    selected_processes_label.insert(tk.END, f"Tracking: {', '.join(tracked_apps)}" if tracked_apps else "No processes selected")
    selected_processes_label.config(state=tk.DISABLED)
    tracking_button.config(state=tk.NORMAL if tracked_apps else tk.DISABLED)

def refresh_process_list():
    if tracking:
        return
    process_listbox.delete(0, tk.END)
    for process in sorted(set(p.info['name'] for p in psutil.process_iter(['name']))):
        process_listbox.insert(tk.END, process)
    selected_processes_label.config(state=tk.NORMAL)
    selected_processes_label.delete(1.0, tk.END)
    selected_processes_label.insert(tk.END, "No processes selected")
    selected_processes_label.config(state=tk.DISABLED)

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

def filter_processes(event):
    search_term = search_entry.get().lower()
    process_listbox.delete(0, tk.END)
    for process in sorted(set(p.info['name'] for p in psutil.process_iter(['name']))):
        if search_term in process.lower():
            process_listbox.insert(tk.END, process)

def close_selected_process():
    selected = process_listbox.curselection()
    if not selected:
        messagebox.showinfo("Info", "No process selected to close.")
        return
    confirmation = messagebox.askyesno("Confirm", "Are you sure you want to terminate the selected process(es)?")
    if not confirmation:
        return
    for i in selected:
        process_name = process_listbox.get(i)
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == process_name:
                try:
                    proc.terminate()
                    messagebox.showinfo("Info", f"Process '{process_name}' has been terminated.")
                    refresh_process_list()
                    break
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    messagebox.showerror("Error", f"Unable to terminate process '{process_name}': {e}")
                    break

root = tk.Tk()
root.title("App Usage Tracker")
root.geometry("1350x600")

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
tk.Button(button_frame, text="Close Process", command=close_selected_process).pack(side=tk.LEFT, padx=5)

selected_processes_label = tk.Text(left_frame, width=50, height=5, wrap=tk.WORD, bg=root.cget("bg"), borderwidth=1, relief="solid")
selected_processes_label.pack(pady=10)
selected_processes_label.config(state=tk.DISABLED)

timer_label = tk.Label(left_frame, text="Tracking Time: 0:00:00", font=("Arial", 12))
timer_label.pack(pady=10)

right_frame = tk.Frame(root)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

log_display = scrolledtext.ScrolledText(right_frame, height=15, borderwidth=1, relief="solid")
log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
log_display.config(state=tk.DISABLED)

report_text = scrolledtext.ScrolledText(right_frame, height=15, borderwidth=1, relief="solid")
report_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
report_text.config(state=tk.DISABLED)

initialize_log()
refresh_process_list()
root.mainloop()
