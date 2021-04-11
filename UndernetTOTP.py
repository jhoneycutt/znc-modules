# Copyright (C) 2021 jotun <jotun@undernet.org>
# Copyright (C) 2013 - 2019 Stefan Wold <ratler@stderr.eu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
# This ZNC module adds automatic OTP (OATH-TOTP) support for Undernet's channel
# service bot (X) and Login on Connect (LoC) authentication.
#
# The module generates an OTP and automatically appends it when it notices a
# /msg x@channels.undernet.org login <username> <password> command or when ZNC
# connects to a server with a connection password. This means you can:
#
#   - Use LoC by setting a server password, or
#   - Use *perform to automatically log into X on connect, or
#   - Log in manually using /msg
#
# And the OTP will automatically appended.
#
# To use this module:
#   1. Install it to ~/.znc/modules/
#   2. /query *status LoadMod modpython
#   3. /query *status LoadMod UndernetTOTP
#   4. /query *UndernetTOTP SetSecret SECRET_GOES_HERE
#   5. Do /query *UndernetTOTP ShowTOTP, and verify that TOTP matches.
#   6. If you want to use LoC, ensure that your server has a password set.
#   7. /query *status SaveConfig
#   8. /query *status Jump
#
# Code and ideas were taken from another script written by Ratler,
# <https://weechat.org/scripts/source/undernet_totp.py.html/>

import hmac
import znc

from base64 import b32decode
from hashlib import sha1
from time import time

TOTP_PERIOD = 30
DEBUG = False

class UndernetTOTP(znc.Module):
    description = "Automatic OTP (OATH-TOTP) authentication with Undernet's channel services (X) and Login on Connect (LoC)."
    module_types = [znc.CModInfo.UserModule, znc.CModInfo.NetworkModule]


    @property
    def secret(self):
        return self.nv.get("Secret")


    @secret.setter
    def secret(self, value):
        self.nv["Secret"] = value


    def PutDebug(self, content):
        if not DEBUG:
            return
        self.PutModule(f"DEBUG: {content}")


    def OnModCommand(self, command):
        command = str(command).strip()
        if not command:
            return

        args = command.split(" ", 1)
        command = args[0].lower()
        if command == "help":
            self.PutModule("\x02ClearSecret\x02: Clear the TOTP secret.")
            self.PutModule("\x02SetSecret <secret>\x02: Set the TOTP secret. Use a 40-char hex string or a base 32 encoded string.")
            self.PutModule("\x02ShowTOTP\x02: Show the current TOTP token.")
            if self.secret is None:
                self.PutModule("-")
                self.PutModule("There is no TOTP secret set. Use SetSecret to set it.")
            return

        if command == "clearsecret":
            self.ClearSecret()
            return

        if command == "setsecret":
            if len(args) < 2:
                self.PutModule("Usage: SetSecret <secret>")
                return

            self.SetSecret(args[1])
            return

        if command == "showtotp":
            self.ShowTOTP()
            return

        self.PutModule("Unknown command. Try 'Help'")


    def OnIRCRegistration(self, password, nick, ident, real_name):
        if not str(password):
            self.PutDebug("No server password is set. Not appending TOTP token.");
            return znc.CONTINUE

        if self.secret is None:
            self.PutDebug(f"Got server pass {password}, but no TOTP secret is set. Not appending TOTP token.")
            return znc.CONTINUE

        token = self.GenerateTOTP()
        self.PutDebug(f"Got pass {password}, appending token {token}.")
        password.s += " " + token
        return znc.CONTINUE


    def OnSendToIRCMessage(self, message):
        if message.GetType() != message.Type_Text:
            return znc.CONTINUE

        message = message.As(znc.CTextMessage)
        target = message.GetTarget().lower()
        if target != "x@channels.undernet.org":
            return znc.CONTINUE

        args = message.GetText().strip().split(" ", 2)
        if len(args) != 3:
            return znc.CONTINUE

        command = args[0].lower()
        if command != "login":
            return znc.CONTINUE

        username = args[1]
        password = args[2]
        token = self.GenerateTOTP()

        message.SetText(f"LOGIN {username} {password} {token}")
        self.PutDebug("Rewrote login command: " + message.GetText())

        return znc.CONTINUE


    def ClearSecret(self):
        del self.nv["Secret"]
        self.PutModule("Secret cleared.")


    def SetSecret(self, secret):
        try:
            self.ParseSecret(secret)
            self.secret = secret
            self.PutModule("Secret set.")
        except Exception as e:
            self.PutModule("Error: Unable to parse secret:")
            self.PutModule(str(e))


    def ParseSecret(self, secret):
        if len(secret) == 40:
            # Assume hex format.
            return bytes.fromhex(secret)
        else:
            return b32decode(secret.replace(" ", ""), True)


    def ShowTOTP(self):
        if self.secret is None:
            self.PutModule("There is no TOTP secret set. Use SetSecret to set it.")
            return
        self.PutModule("Current token: " + self.GenerateTOTP())


    def GenerateTOTP(self):
        seed = self.ParseSecret(self.secret)
        time_qword = int(time() / TOTP_PERIOD).to_bytes(8, byteorder='big')
        mac = hmac.new(seed, time_qword, sha1).digest()
        offset = mac[19] & 15
        otp = (int.from_bytes(mac[offset:offset+4], byteorder='big') & 0x7fffffff) % 1000000
        return f"{otp:06}"

