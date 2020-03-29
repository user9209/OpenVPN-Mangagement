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
    OpenvpnLogin.jar list
    
    # Add a user:
    OpenvpnLogin.jar add <username> <password>
    
    # Update a user:
    OpenvpnLogin.jar update <username> <password>
    
    # Delete a user:
    OpenvpnLogin.jar update <username> <random data (size 22+)>
    
    # Login:
    OpenvpnLogin.jar
    
    # Connect history:
    OpenvpnLogin.jar history
    
    # Connect to VPN
    OpenvpnLogin.jar connect
    
    # Disconnect to VPN
    OpenvpnLogin.jar disconnect

## Setup ##

    java -jar /etc/openvpn/script/OpenvpnLogin.jar add <username> <password>

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

## FAQ ##

### Question: The login is extrem slow? ###

Thats normal. BCrypt is slow based on its design.
To speed up the login reduce the bcrypt cost parameter.
Default is 12. Limit is 32 (you will not be able to compute a single hash).
So use something that takes 500 ms to 3 s on you system.

After changing the bcrypt cost parameter you need to update ALL
current passwords! Only at setting passwords the parameter is used!



### Question: How to backup the users? ###

Simply copy the *.db - files.

### Question: Is the database permanently open? ###

No, the program opens the database, performs actions and closes the database.

### Question: Setup script to setup openvpn? ###

This is plant in a future release for debian.


### Question: Can it generate and manage the CA and user certs? ###

Currently no. This is plant in a future release for openssl on debian.
At windows you may like XCA.