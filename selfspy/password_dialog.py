# Copyright 2012 David Fendrich

# This file is part of Selfspy

# Selfspy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Selfspy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Selfspy.  If not, see <http://www.gnu.org/licenses/>.

import sys
import getpass

import keyring
import tkinter
import tkinter.simpledialog


def get_password(verify=None, message=None):
    if not verify:
        pw = get_user_password(verify, message)
    else:
        pw = get_keyring_password(verify)

    if pw == None:
        pw = get_user_password(verify, message)

    return pw


def get_user_password(verify, message=None, force_save=False):
    if sys.stdin.isatty():
        pw = get_tty_password(verify, message, force_save)
    else:
        pw = get_tk_password(verify, message, force_save)

    return pw


def get_keyring_password(verify, message=None):
    pw = keyring.get_password('Selfspy', getpass.getuser())
    if pw is not None:
        if not verify or not verify(pw):
            print('The keyring password is not valid. Please, input the correct one.')
            pw = get_user_password(verify, message, force_save=True)
    return pw


def set_keyring_password(password):
    usr = getpass.getuser()
    keyring.set_password('Selfspy', usr, password)


def get_tty_password(verify, message=None, force_save=False):
    verified = False
    for i in range(3):
        if message:
            pw = getpass.getpass(message)
        else:
            pw = getpass.getpass()
        if (not verify) or verify(pw):
            verified = True
            break

    if not verified:
        print('Password failed')
        sys.exit(1)

    if not force_save:
        while True:
            store = input("Do you want to store the password in the keychain [Y/N]: ")
            if store.lower() in ['n', 'y']:
                break
        save_to_keychain = store.lower() == 'y'
    else:
        save_to_keychain = True

    if save_to_keychain:
        set_keyring_password(pw)

    return pw


def get_tk_password(verify, message=None, force_save=False):
    root = tkinter.Tk()
    root.withdraw()
    if message is None:
        message = 'Password'

    while True:
        dialog_info = PasswordDialog(title='Selfspy encryption password',
                            prompt=message,
                            parent=root)

        pw, save_to_keychain = dialog_info.result

        if pw is None:
            return ""

        if (not verify) or verify(pw):
            break

    if save_to_keychain or force_save:
        set_keyring_password(pw)

    return pw


class PasswordDialog(tkinter.simpledialog.Dialog):

    def __init__(self, title, prompt, parent):
        self.prompt = prompt
        tkinter.simpledialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        self.checkVar = tkinter.IntVar()

        tkinter.Label(master, text=self.prompt).grid(row=0, sticky=tkinter.W)

        self.e1 = tkinter.Entry(master)

        self.e1.grid(row=0, column=1)

        self.cb = tkinter.Checkbutton(master, text="Save to keychain", variable=self.checkVar)
        self.cb.pack()
        self.cb.grid(row=1, columnspan=2, sticky=tkinter.W)
        self.e1.configure(show='*')

    def apply(self):
        self.result = (self.e1.get(), self.checkVar.get() == 1)


if __name__ == '__main__':
    print(get_password())
