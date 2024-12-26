from tkinter import *
import customtkinter


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("green")


def start_gui():
    root = customtkinter.CTk()
    root.title('Advanced Sniffer')
    # root.iconbitmap('')
    root.geometry('600x350')

    starting_button = customtkinter.CTkButton(root, text="Starting")
    starting_button.pack(pady=80)

    root.mainloop()