# OpenVPN-Mangagement #

Copyright (C) 2018  Georg Schmidt <gs-develop@gs-sys.de>
GPL 3.0

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

---

    auth-user-pass-verify /etc/openvpn/script/login.sh via-env

---

Future (not implemented yet)

    script-security 3 system
    client-connect /etc/openvpn/script/connect.sh
    client-disconnect /etc/openvpn/script/disconnect.sh
