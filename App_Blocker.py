"""
App Blocker with Password Protected Stop - Python script that runs in the background and instantly terminates any user-launched applications,
effectively preventing the user from opening any app except for allowed ones (whitelist).

WARNING:
- This script requires administrator privileges to terminate other processes.
- Use responsibly and ONLY on systems where you have permission.
- This app runs indefinitely and has no visible UI window,
  cannot be closed easily without killing the process externally or entering password.
- Can be stopped only by pressing Ctrl + Alt + S and entering the correct password.

Usage:
- Run this script on Windows with admin privileges.
- To stop, press Ctrl + Alt + S and enter the password.

Dependencies:
 - psutil (install via `pip install psutil`)
 - keyboard (install via `pip install keyboard`)

"""

import psutil
import os
import sys
import time
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import keyboard
import queue

# Allowed processes whitelist
ALLOWED_PROCESSES = {
    "System Idle Process",
    "System",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "python.exe",
    "pythonw.exe",
    os.path.basename(sys.executable).lower(),
}

def is_allowed_process(proc_name: str) -> bool:
    return proc_name.lower() in (name.lower() for name in ALLOWED_PROCESSES)

class AppBlocker:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.stop_event = threading.Event()
        self.password_prompt_queue = queue.Queue()

        # Set up the keyboard hotkey to request stop
        # The hotkey callback runs in a separate thread by keyboard lib, so only enqueue an event
        keyboard.add_hotkey('ctrl+alt+s', self.request_stop)

        # Schedule periodic check for password prompt event in tkinter mainloop
        self.root.after(100, self.check_password_prompt)
        
        # Start process monitoring in background thread
        self.monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.monitor_thread.start()

    def request_stop(self):
        # Called on hotkey from keyboard thread
        # Put a signal in the queue to show password prompt in main thread
        self.password_prompt_queue.put(True)

    def check_password_prompt(self):
        # Called periodically in tkinter mainloop
        try:
            while True:
                _ = self.password_prompt_queue.get_nowait()
                self.ask_password_and_stop()
        except queue.Empty:
            pass
        self.root.after(100, self.check_password_prompt)

    def ask_password_and_stop(self):
        # Show password dialog safely in main thread
        password = simpledialog.askstring("Password Required", 
                                          "Enter password to stop the app blocker:", 
                                          show='*', 
                                          parent=self.root)
        if password == "4329":
            messagebox.showinfo("Access Granted", "Stopping the app blocker.", parent=self.root)
            self.stop_event.set()
            self.root.quit()
        else:
            messagebox.showerror("Access Denied", "Incorrect password!", parent=self.root)

    def monitor_processes(self):
        print("App Blocker started. Running in background. Press Ctrl + Alt + S to stop.")
        known_pids = set(p.pid for p in psutil.process_iter())

        while not self.stop_event.is_set():
            try:
                current_pids = set(p.pid for p in psutil.process_iter())
                new_pids = current_pids - known_pids
                if new_pids:
                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()

                            if not is_allowed_process(proc_name):
                                proc.terminate()
                                try:
                                    proc.wait(timeout=3)
                                except psutil.TimeoutExpired:
                                    proc.kill()
                                print(f"Terminated disallowed process: {proc_name} (PID: {pid})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                known_pids = current_pids
                time.sleep(0.5)
            except Exception as e:
                print(f"Error in process monitoring: {e}")
                time.sleep(1)

def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    app_blocker = AppBlocker(root)
    # Run the tkinter event loop; will exit on correct password
    root.mainloop()
    print("App Blocker stopped.")

if __name__ == "__main__":
    main()

