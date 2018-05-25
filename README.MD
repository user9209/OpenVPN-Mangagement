# OpenVPN-Mangagement #

Copyright (C) 2018  Georg Schmidt < gs-develop<span></span>@gs-sys.de >  
GPL 3.0

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

This software allows you to manage password authentication using OpenVPN.  
Passwords are securely stored as BCrypt-Hashes.

    ##############################################################################################
    # WARNING:                                                                                   #
    #         If using "user nobody" every user id on the system can change any log information! #
    #         The following config uses this unsecure way with "user nobody"!                    #
    #         Passwords can only hardly stolen as the BCrypt-Hash has to be hacked.              #
    ##############################################################################################

---

## Usage ##

    auth-user-pass-verify /etc/openvpn/script/login.sh via-env
    script-security 3 system
    client-connect /etc/openvpn/script/connect.sh
    client-disconnect /etc/openvpn/script/disconnect.sh

---

    # List all user:
    xyz.jar list

    # Add a user:
    xyz.jar add <username> <password>

    # Update a user:
    xyz.jar update <username> <password>

    # Delete a user:
    xyz.jar update <username> <random data (size 22+)>

    # Login:
    xyz.jar login

    # Connect history:
    xyz.jar history

    # Connect to VPN
    xyz.jar connect

    # Disconnect to VPN
    xyz.jar disconnect

## Setup ##

    /etc/openvpn/script/OpenvpnLogin.jar add <username> <password>

## Requirements ##

    # Files
    /etc/openvpn/script/OpenvpnLogin.jar
    /etc/openvpn/script/connect.sh
    /etc/openvpn/script/disconnect.sh
    /etc/openvpn/script/login.sh

---

User datebase accessable for anybody! Passwords protected by bcrypt.

    chown root /etc/openvpn/script/vpnuser.db
    chmod 644 /etc/openvpn/script/vpnuser.db

To write vpnlog.db connect and disconnect to database:

    chmod 777 /etc/openvpn/script/

Not enough for writing:

    chmod 666 /etc/openvpn/script/vpnlog.db

---

Other scripts
must be runnable by everybody

    chmod 755 /etc/openvpn/script/*.sh
