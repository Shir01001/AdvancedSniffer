import tkinter as tk
from tkinter import ttk



def start_gui():
    root = tk.Tk()

    root.tk.call('source', './assets/gui_theme/forest-dark.tcl')
    ttk.Style().theme_use('forest-dark')

    root.title('Advanced Sniffer')
    root.iconbitmap('')
    root.geometry('600x350')


    root.mainloop()