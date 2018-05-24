# OpenVPN-Mangagement #

Copyright (C) 2018  Georg Schmidt <gs-develop@gs-sys.de>  
GPL 3.0

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

---

## Usage ##

    auth-user-pass-verify /etc/openvpn/script/login.sh via-env
    script-security 3 system
    client-connect /etc/openvpn/script/connect.sh
    client-disconnect /etc/openvpn/script/disconnect.sh

---

## Setup ##

    /etc/openvpn/script/OpenvpnLogin.jar add <username> <password>

## Requirements ##

    # Files
    /etc/openvpn/script/OpenvpnLogin.jar
    /etc/openvpn/script/connect.sh
    /etc/openvpn/script/disconnect.sh
    /etc/openvpn/script/login.sh

---

    # to write vpnuser.db connect and disconnect to database:
    chmod 707 /etc/openvpn/script/

---

    # not enough:
    chmod 606 /etc/openvpn/script/vpnuser.db

---

    # other scripts
    # must be runnable by everybody

    chmod 705 /etc/openvpn/script/*.sh



