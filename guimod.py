import tkinter as tk
from tkinter import ttk
import threading
import queue
import os

class Gui(tk.Frame):
    
    def __init__(self, root, client):
        self.bg = "#f1f1f1"
        self.fg = "#ffffff"
        self.entry_bg = "#ffffff"
        self.gui_style = ttk.Style()
        self.gui_style.configure('gui.TNotebook', background=self.bg, padding=3)
        self.sentinel = object()
        self.root = root
        self.client = client
        tk.Frame.__init__(self, root, bg=self.bg)
        root.resizable(width=False, height=False)
        root.minsize(width=800, height=400)
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        root.title("OTPIRC Client")
        self.grid(row=0, column=0, sticky=tk.E+tk.W+tk.N+tk.S)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.initialize_otp_config()
        self.initialize_login()
        self.initialize_app()
        self.otp_visible = False
        self.files = []

    def connect(self):
        self.login_frame.grid_forget()
        self.app_frame.grid(row=0, column=0, sticky=tk.N)
        self.client.connect()

    def configure_otp(self):
        self.app_frame.grid_forget()
        self.otp_config_frame.grid(row=0, column=0, sticky=tk.N+tk.E+tk.S+tk.W)
        self.update_available_files()

    def go_otp(self):
        self.otp_config_frame.grid_forget()
        self.app_frame.grid(row=0, column=0, sticky=tk.N)

    def generate_keys(self):
        self.genoptions_frame.grid_forget()
        self.genprogress_frame.grid(row=0, column=0)
        self.alp = self.genop_alphabet_entry.get()
        self.lenmsg = self.genop_msglen_entry.get()
        self.keyno = self.genop_keynum_entry.get()
        self.genpro_progressbar.config(value=0)
        outqueue = queue.Queue()
        t = threading.Thread(target=self.generate, args=(outqueue, None))
        t.start()
        self.root.after(250, self.update, outqueue)

    def generate(self, outqueue, placeholder):
        self.client.set_otp(self.alp,self.lenmsg,self.keyno,self.file,outqueue)

    def update(self, outqueue):
        try:
            msg = outqueue.get_nowait()
            if msg is not self.sentinel:
                if not msg == "Stopped":
                    self.root.after(10, self.update, outqueue)
                    if msg == "Step":
                        self.genpro_progressbar.step()
                else:
                    self.return_to_genoptions()
            else:
                pass
        except queue.Empty:
            self.root.after(10, self.update, outqueue)

    def return_to_genoptions(self):
        self.genprogress_frame.grid_forget()
        self.genoptions_frame.grid(row=0, column=0, sticky=tk.N+tk.E+tk.S+tk.W)
        self.update_available_files()
        self.update_selected_file()

    def on_generate_button_press(self):
        self.file = self.genop_filename_entry.get()
        self.generate_keys()

    def select_file_from_box(self, event):
        self.file = self.availablefiles_listbox.get(tk.ACTIVE).replace(".dict","")
        self.generate_keys()

    def update_selected_file(self):
        self.selected_entry.delete(0, tk.END)
        self.selected_entry.insert(tk.END, self.availablefiles_listbox.get(tk.ACTIVE))

    def update_available_files(self):
        for file in os.listdir():
            if file.endswith(".dict") and file not in self.files:
                self.files.append(file)
                self.availablefiles_listbox.insert(tk.END, file)
    
    def send(self):
        self.client.send_server_msg()
        self.input_entrytext.set("")

    def onPressEnter(self, event):
        self.send()

    def onAddrEnter(self, event):
        self.port_entry.focus_set()
        
    def onPortEnter(self, event):
        self.nick_entry.focus_set()
        
    def onNickEnter(self, event):
        self.user_entry.focus_set()
        
    def onUserEnter(self, event):
        self.connect()

    def toggle_otp(self):
        if self.otp_visible:
            self.otp_visible = False
            self.client.otp_enabled = False
            self.encode_text.grid_forget()
        else:
            self.otp_visible = True
            self.client.otp_enabled = True
            self.encode_text.grid(row=3, column=0, columnspan=5, sticky=tk.E+tk.W)

    def join_room(self, room=None):
        if room == None:
            room = "#OTPDefault"
        self.client.send_server_msg("/JOIN {}".format(room))

    def initialize_otp_config(self):
        self.otp_config_frame = tk.Frame(self, bg=self.bg)
        self.otp_config_frame.grid_rowconfigure(0, weight=1)
        self.otp_config_frame.grid_rowconfigure(1, weight=0)
        self.otp_config_frame.grid_rowconfigure(2, weight=4)
        self.otp_config_frame.grid_columnconfigure(0, weight=1)
        self.otp_config_frame.grid_columnconfigure(1, weight=1)

        otpoption_label = tk.Label(self.otp_config_frame, bg=self.bg, text="OTP Options")
        otpoption_label.grid(row=0, column=0, sticky=tk.N+tk.W)
        availablefiles_label = tk.Label(self.otp_config_frame, bg=self.bg, text="Available files (double click to select):")
        availablefiles_label.grid(row=1, column=0, sticky=tk.N+tk.W)
        self.availablefiles_listbox = tk.Listbox(self.otp_config_frame, width=40)
        self.availablefiles_listbox.grid(row=2, column=0, sticky=tk.N+tk.E+tk.S+tk.W)
        self.availablefiles_listbox.bind("<Double-Button-1>", self.select_file_from_box)
        generation_frame = tk.Frame(self.otp_config_frame, bg=self.bg)
        generation_frame.grid(row=1, column=1, rowspan=2, columnspan=3)
        generation_frame.grid_rowconfigure(0, weight=1)
        self.genoptions_frame = tk.Frame(generation_frame, bg=self.bg)
        self.genoptions_frame.grid(row=0, column=0, sticky=tk.N+tk.E+tk.S+tk.W)
        genop_new_label = tk.Label(self.genoptions_frame, bg=self.bg, text="Generate new OTP key dictionary\nLeave blank for defaults (recommended)", pady=20)
        genop_new_label.grid(row=0, column=0, columnspan=3, sticky=tk.N)
        genop_alphabet_label = tk.Label(self.genoptions_frame, bg=self.bg, text="Allowed characters:")
        genop_alphabet_label.grid(row=1, column=0, sticky=tk.W)
        self.genop_alphabet_entry = tk.Entry(self.genoptions_frame, bg=self.entry_bg)
        self.genop_alphabet_entry.grid(row=1, column=1)
        genop_msglen_label = tk.Label(self.genoptions_frame, bg=self.bg, text="Message length limit:")
        genop_msglen_label.grid(row=2, column=0, sticky=tk.W)
        self.genop_msglen_entry = tk.Entry(self.genoptions_frame, bg=self.entry_bg)
        self.genop_msglen_entry.grid(row=2, column=1)
        genop_keynum_label = tk.Label(self.genoptions_frame, bg=self.bg, text="Number of keys:")
        genop_keynum_label.grid(row=3, column=0, sticky=tk.W)
        self.genop_keynum_entry = tk.Entry(self.genoptions_frame, bg=self.entry_bg)
        self.genop_keynum_entry.grid(row=3, column=1)
        spacer1 = tk.Label(self.genoptions_frame, bg=self.bg)
        spacer1.grid(row=4, column=0)
        genop_filename_label = tk.Label(self.genoptions_frame, bg=self.bg, text="Filename:")
        genop_filename_label.grid(row=5, column=0, sticky=tk.W+tk.S)
        self.genop_filename_entry = tk.Entry(self.genoptions_frame, bg=self.entry_bg)
        self.genop_filename_entry.grid(row=5, column=1)
        genop_generate_button = tk.Button(self.genoptions_frame, text="Generate", command=self.on_generate_button_press)
        genop_generate_button.grid(row=1, column=2, rowspan=5, sticky=tk.N+tk.S)
        self.genprogress_frame = tk.Frame(generation_frame, bg=self.bg)
        self.genpro_progressbar = ttk.Progressbar(self.genprogress_frame, length=240)
        self.genpro_progressbar.grid(row=0, column=0)
        genpro_cancel_button = tk.Button(self.genprogress_frame, text="Cancel", command=self.return_to_genoptions)
        genpro_cancel_button.grid(row=1, column=0)
        selected_label = tk.Label(self.otp_config_frame, bg=self.bg, text="Selected:")
        selected_label.grid(row=3, column=1, sticky=tk.E)
        self.selected_entry = tk.Entry(self.otp_config_frame, bg=self.entry_bg, width=40)
        self.selected_entry.grid(row=3, column=2, sticky=tk.W)
        select_button = tk.Button(self.otp_config_frame, text="Go", command=self.go_otp)
        select_button.grid(row=3, column=3)

    def initialize_login(self):
        self.login_frame = tk.Frame(self, bg=self.bg)
        self.login_frame.grid(row=0, column=0)
        self.login_frame.grid_rowconfigure(0, weight=0)
        self.login_frame.grid_columnconfigure(0, weight=1)

        otpexpl_label = tk.Label(self.login_frame, bg=self.bg, justify=tk.LEFT, text=
"""In cryptography, the one-time pad (OTP)
is an encryption technique that cannot be cracked                

If the key is truly random,
is at least as long as the plaintext,
is never reused in whole or in part,
and is kept completely secret,
then the resulting ciphertext will be
impossible to decrypt or break""")
        otpexpl_label.grid(row=0, column=0, rowspan=9, sticky=tk.W)
        login_config_frame = tk.Frame(self.login_frame, bg=self.bg)
        login_config_frame.grid(row=0, column=1)
        addr_label = tk.Label(login_config_frame, bg=self.bg, text="Address:")
        addr_label.grid(row=0, column=1)
        self.addr_entry = tk.Entry(login_config_frame, bg=self.entry_bg)
        self.addr_entry.grid(row=1, column=1)
        self.addr_entry.insert(tk.END, "127.0.0.1")
        self.addr_entry.focus_set()
        self.addr_entry.bind("<Return>", self.onAddrEnter)
        port_label = tk.Label(login_config_frame, bg=self.bg, text="Port:")
        port_label.grid(row=2, column=1)
        self.port_entry = tk.Entry(login_config_frame, bg=self.entry_bg)
        self.port_entry.grid(row=3, column=1)
        self.port_entry.insert(tk.END, "6667")
        self.port_entry.bind("<Return>", self.onPortEnter)
        nick_label = tk.Label(login_config_frame, bg=self.bg, text="Nick:")
        nick_label.grid(row=4, column=1)
        self.nick_entry = tk.Entry(login_config_frame, bg=self.entry_bg)
        self.nick_entry.grid(row=5, column=1)
        self.nick_entry.insert(tk.END, "test")
        self.nick_entry.bind("<Return>", self.onNickEnter)
        user_label = tk.Label(login_config_frame, bg=self.bg, text="Username:")
        user_label.grid(row=6, column=1)
        self.user_entry = tk.Entry(login_config_frame, bg=self.entry_bg)
        self.user_entry.grid(row=7, column=1)
        self.user_entry.insert(tk.END, "testuser")
        self.user_entry.bind("<Return>", self.onUserEnter)
        connect_button = tk.Button(login_config_frame, text="Connect", command=self.connect)
        connect_button.grid(row=8, column=1, pady=10)

    def initialize_app(self):
        self.app_frame = tk.Frame(self, bg=self.bg, padx=10, pady=10, borderwidth=1)#, relief=tk.RAISED)
        self.app_frame.grid_columnconfigure(0, weight=0)
        self.app_frame.grid_columnconfigure(1, weight=0)
        self.app_frame.grid_columnconfigure(2, weight=5)
        self.app_frame.grid_columnconfigure(3, weight=0)
        self.app_frame.grid_columnconfigure(4, weight=2)
        
        channel_tabs_frame = tk.Frame(self.app_frame, bg=self.bg)
        channel_tabs_frame.grid(row=0, column=0, rowspan=2, columnspan=4)
        self.notebook = ttk.Notebook(channel_tabs_frame, style='gui.TNotebook')
        self.notebook.grid(row=0, column=0)
        self.notebook_frames = {}
        self.notebook_frames['Main'] = tk.Frame(self.notebook, bg=self.bg)
        self.notebook_frames['Main'].configure(width=80)
        self.notebook_outputs = {}
        self.notebook_outputs['Main'] = tk.Text(self.notebook_frames['Main'], width=80, height=18)
        self.notebook_outputs['Main'].config(state=tk.DISABLED)
        self.notebook_outputs['Main'].grid(row=0 ,column=0)
        join_button = tk.Button(self.notebook_frames['Main'], text="Join Default Room", pady=3, command=self.join_room)
        join_button.grid(row=1, column=0, sticky=tk.N+tk.S)
        self.notebook.add(self.notebook_frames['Main'], text="Main")
        
        otp_config_button = tk.Button(self.app_frame, text="OTP Config", command=self.configure_otp)
        otp_config_button.grid(row=0, column=4, sticky=tk.E+tk.W)
        encode_check_label = tk.Label(self.app_frame, text="OTP:", bg=self.bg)
        encode_check_label.grid(row=2, column=0)
        encode_check = tk.Checkbutton(self.app_frame, width=1, command=self.toggle_otp, bg=self.bg)
        encode_check.grid(row=2, column=1, sticky=tk.W)
        self.input_entrytext = tk.StringVar()
        self.input_entry = tk.Entry(self.app_frame, textvariable=self.input_entrytext)
        self.input_entry.grid(row=2, column=2, sticky=tk.E+tk.W)
        self.input_entry.bind("<Return>",self.onPressEnter)
        send_button = tk.Button(self.app_frame, text="Send", command=self.send)
        send_button.grid(row=2, column=3, sticky=tk.E)
        chan_user_frame = tk.Frame(self.app_frame, bg=self.bg)
        chan_user_frame.grid(row=1, column=4, rowspan=2, sticky=tk.N+tk.S)
        chan_user_frame.grid_rowconfigure(0, weight=1)
        self.channel_list = tk.Text(chan_user_frame, width=15, height=10)
        self.channel_list.config(state=tk.DISABLED)
        self.channel_list.grid(row=0, column=0, sticky=tk.N)
        user_list = tk.Text(chan_user_frame, width=15, height=10)
        user_list.insert(tk.END, "Commands:\n/JOIN #channel\n/PRIVATE user\n/PART chan msg")
        user_list.config(state=tk.DISABLED)
        user_list.grid(row=1, column=0, sticky=tk.S)
        self.encode_text = tk.Text(self.app_frame, height=5)
        self.encode_text.config(state=tk.DISABLED)

if __name__ == '__main__':
    class dummy_client():
        def set_otp(*args):
            pass
        def connect(*args):
            pass
        def send_server_msg(*args):
            pass

    client = dummy_client()
    root = tk.Tk()
    gui = Gui(root, client)
