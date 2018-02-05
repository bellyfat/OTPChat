import socket
import threading

from otpmod import *
from guimod import *

class UserInputError(Exception):
    pass


class Client():

    def __init__(self, root, CONNECT):
        self.gui = Gui(root, self)
        self.s = socket.socket()
        self.known_channels = []
        self.known_users = []
        self.otp = None
        self.otp_enabled = False
        self._connect = CONNECT
        self.exclude_msg = ['001','002','003','004','005','396','251','255','265','266','422','PING','MODE']
        self.allow_raw_msg = False

    def set_otp(self, alphabet, message_length, key_number, file, outqueue):
        if alphabet == "":
            alphabet = OTP.defaults_alphabet
        if message_length == "":
            message_length = OTP.defaults_message_length
        else:
            message_length = int(message_length)
        if key_number == "":
            key_number = OTP.defaults_key_number
        else:
            key_number = int(key_number)
        if file == "":
            file = OTP.defaults_file
        else:
            file += ".dict"
        self.otp = OTP(alphabet, message_length, key_number, file, outqueue)
    
    def connect(self):
        HOST = self.gui.addr_entry.get()
        PORT = int(self.gui.port_entry.get())
        self.NICK = self.gui.nick_entry.get()
        USER = self.gui.user_entry.get()
        self.joined_channels = []
        if self._connect:
            self.s.connect((HOST, PORT))
            self.gui.root.title("OTPIRC Client - User: {} - Connected: {}".format(self.NICK, HOST))
            self.print_tab('Main', "Connected: {}".format(HOST))
            t = threading.Thread(target=self.read_server_msg)
            t.daemon = True
            t.start()
            self.s.send("NICK {}\r\n".format(self.NICK).encode())
            self.s.send("USER {} {} * :{}\r\n".format(self.NICK, 0, USER).encode())
            self.gui.input_entry.focus_set()

    def create_and_select_frame(self, tab, select=False):
        self.gui.notebook_frames[tab] = tk.Frame(self.gui.notebook, bg=self.gui.bg)
        self.gui.notebook_outputs[tab] = tk.Text(self.gui.notebook_frames[tab], width=80, height=20)
        self.gui.notebook_outputs[tab].config(state=tk.DISABLED)
        self.gui.notebook_outputs[tab].grid(row=0, column=0)
        self.gui.notebook.add(self.gui.notebook_frames[tab], text=tab)
        if select:
            self.gui.notebook.select(self.gui.notebook_frames[tab])

    def print_tab(self, tab, message, *args):
        self.gui.notebook_outputs[tab].config(state=tk.NORMAL)
        self.gui.notebook_outputs[tab].insert(tk.END, message.format(*args).strip()+"\n")
        self.gui.notebook_outputs[tab].see(tk.END)
        self.gui.notebook_outputs[tab].config(state=tk.DISABLED)

    def interpret_user_input(self, msg=None):
        send_message = True
        tab = self.gui.notebook.tab(self.gui.notebook.select(), "text")
        if msg == None:
            msg = self.gui.input_entrytext.get()
        try:
            if tab == "Main" and not msg[0] == "/":
                if not self.allow_raw_msg:
                    send_message = False
                    self.print_tab(tab, "Unknown command\n")
            else:
                if msg[0] == "/":
                    msg = msg[1:]
                    command = msg.split()
                    if command[0].upper() == "JOIN":
                        if len(command) < 2:
                            raise UserInputError('missing argument')
                        if command[1] not in self.joined_channels:
                            if command[1][0] == "#":
                                self.joined_channels.append(command[1])
                                self.create_and_select_frame(command[1], True)
                        else:
                            raise UserInputError('already in room')
                    elif command[0].upper() == "PRIVATE":
                        send_message = False
                        if len(command) < 2:
                            raise UserInputError('missing argument')
                        if command[1] not in self.joined_channels:
                            print("starting private conversation with: {}".format(command[1]))
                            self.joined_channels.append(command[1])
                            self.create_and_select_frame(command[1], True)
                        else:
                            raise UserInputError('already in conversation')
                    elif command[0].upper() == "PART":
                        if not tab == "Main":
                            arg_len = len(command)
                            if arg_len == 1:
                                self.gui.notebook.forget(self.gui.notebook_frames[tab])
                                self.joined_channels.remove(tab)
                                msg += " {}".format(tab)
                                if not tab[0] == "#":
                                    send_message = False
                            elif arg_len >= 2:
                                self.gui.notebook.forget(self.gui.notebook_frames[command[1]])
                                self.joined_channels.remove(command[1])
                                if not tab[0] == "#":
                                    send_message = False
                        else:
                            raise UserInputError('not currently in room or conversation')
                    elif command[0].upper() == "LIST":
                        pass
                    elif command[0].upper() == "NAMES":
                        pass
                    elif command[0].upper() == "WHOIS":
                        pass
                    elif command[0].upper() == "OPER":
                        pass
                    else:
                        send_message = False
                        self.print_tab(tab, "Unknown command\n")
                else:
                    if self.otp_enabled:
                        if not self.otp == None:
                            encode_text_msg = msg
                            msg, send_message = self.otp.encode(msg)
                            if send_message:
                                self.gui.encode_text.config(state=tk.NORMAL)
                                self.gui.encode_text.insert(tk.END, "{}: {}\n".format(self.NICK, encode_text_msg))
                                self.gui.encode_text.see(tk.END)
                                self.gui.encode_text.config(state=tk.DISABLED)
                        else:
                            send_message = False
                            msg = "OTP not configured"
                    if send_message:
                        self.print_tab(tab, "{}: {}\n", self.NICK, msg)
                    else:
                        self.print_tab(tab, "{}\n", msg)
                    msg = "PRIVMSG {} {}".format(tab, msg)
            if send_message:
                return(msg)
            else:
                return("")
        except UserInputError as e:
            self.print_tab(tab, "input error: {}\n", e)
            return("")
        except IndexError:
            print("IndexError: Can't send 0 length message")
            return("")

    def send_server_msg(self, message=None):
        msg = self.interpret_user_input(message)
        if self._connect:
            self.s.send("{}\r\n".format(msg).encode())

    def parse_msg(self, s):
        #IRC message parser from http://twistedmatrix.com/trac/browser/trunk/twisted/words/protocols/irc.py#54
        prefix = ''
        trailing = []
        if not s:
            raise IRCBadMessage("Empty line.")
        if s[0] == ':':
            prefix, s = s[1:].split(' ', 1)
        if s.find(' :') != -1:
            s, trailing = s.split(' :', 1)
            args = s.split()
            args.append(trailing)
        else:
            args = s.split()
        command = args.pop(0)
        return(prefix, command, args)

    def read_server_msg(self):
        read_buffer = ""
        while True:
            read_buffer += self.s.recv(1024).decode()
            tmp = read_buffer.split("\n")
            read_buffer = tmp.pop()
            print_to_main = True
            for line in tmp:
                prefix, command, args = self.parse_msg(line)
                if command == "PING":
                    self.s.send("PONG {}\n".format(args[0]).encode())
                elif command == "PRIVMSG":
                    msg = args[1].strip("\r\n")
                    target_tab = args[0]
                    if args[0] == self.NICK:
                        other_user = prefix.split("!")[0]
                        if other_user not in self.joined_channels:
                            self.create_and_select_frame(other_user, False)
                            self.joined_channels.append(other_user)
                        target_tab = other_user
                    if self.otp == None:
                        pass
                    else:
                        if len(msg) == self.otp.n + self.otp.get_key_len(self.otp.MAX_KEYS):
                            try:
                                int(msg[:self.otp.get_key_len(self.otp.MAX_KEYS)],16)
                                msg = self.otp.decode(msg)
                                self.gui.encode_text.config(state=tk.NORMAL)
                                self.gui.encode_text.insert(tk.END, "{}: {}\n".format(prefix.split('!')[0], msg))
                                self.gui.encode_text.config(state=tk.DISABLED)
                            except ValueError:
                                print("dunno")
                    self.print_tab(target_tab, "{}: {}\n", prefix.split("!")[0], args[1].strip('\r\n'))
                elif command == "JOIN":
                    target_tab = args[0].strip("\r\n")
                    other_user = prefix.split("!")[0]
                    self.print_tab(target_tab, "{} joined\n", other_user)
                elif command == "PART":
                    target_tab = args[0].strip("\r\n")
                    other_user = prefix.split("!")[0]
                    self.print_tab(target_tab, "{} left\n", other_user)
                elif command == "NOTICE":
                    print_to_main = False
                    self.print_tab('Main', "{}", args[1].strip("*"))
                elif command == "375":
                    print_to_main = False
                elif command == "372":
                    print_to_main = False
                    self.print_tab('Main', "{}", args[1].lstrip("- "))
                elif command == "376":
                    print_to_main = False
                elif command == "322":
                    if not args[1] in self.known_channels:
                        self.known_channels.append(args[1])
                        self.gui.channel_list.config(state=tk.NORMAL)
                        self.gui.channel_list.delete('1.0', tk.END)
                        for channel in self.known_channels:
                            self.gui.channel_list.insert(tk.END, "{}\n".format(channel))
                        self.gui.channel_list.config(state=tk.DISABLED)
                elif command == "401":
                    tab = self.gui.notebook.tab(self.gui.notebook.select(), "text")
                    self.print_tab(tab, "{}\n", line)
                if command not in self.exclude_msg and print_to_main:
                    self.print_tab('Main',"{}\n",line)
