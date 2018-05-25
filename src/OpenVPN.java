/*
    Copyright (C) 2018  Georg Schmidt <gs-develop@gs-sys.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// https://docs.spring.io/spring-security/site/docs/4.2.4.RELEASE/apidocs/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Map;


public class OpenVPN extends ConncetDisconnectModule {

    private static String DB_FILE;

    static {
        try {
            DB_FILE = URLDecoder.decode(new File(OpenVPN.class.getProtectionDomain().getCodeSource().getLocation()
                    .getPath()).getParentFile().getPath(), "UTF-8") + File.separator +  "vpnuser.db";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private static Connection c = null;
    private static BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);


    public static void main(String ... args) {

        int exitCode = -1;

        if(!Files.exists(Paths.get(DB_FILE)))
        {

            sqlSetup();
            setupSQLConDiscon();
        }

        if(args.length == 1)
        {
            switch (args[0]) {
                case "login":
                    Map<String, String> env = System.getenv();
                    /*
                    for (String envName : env.keySet()) {
                        System.out.format("%s=%s%n", envName, env.get(envName));
                    }
                    */

                    String username = env.get("username");
                    String password = env.get("password");

                    sqlOpen();
                    if(username != null && password != null && loginUser(username,password))
                    {
                        exitCode = 0;
                    }
                    else {
                        System.err.println("Login username '" + username + "' failed!");
                    }
                    break;

                case "list":
                    sqlOpen();
                    System.out.println(listUser());
                    break;
                case "history":
                    openSQLConDiscon();
                    System.out.println(history());
                    break;
                case "connect":
                    openSQLConDiscon();
                    Map<String, String> env1 = System.getenv();
                    if(connect(env1)) {
                        exitCode = 0;
                    }
                    break;
                case "disconnect":
                    openSQLConDiscon();
                    Map<String, String> env2 = System.getenv();
                    if(disconnect(env2)) {
                        exitCode = 0;
                    }
                    break;
                default:

                    help();
                    break;
            }
        }
        else if(args.length == 3)
        {
            if (args[0].equals("add"))
            {
                sqlOpen();
                if(insertUser(args[1],args[2]))
                {
                    System.out.println("User '" + args[1] + "' added.");
                }
                else {
                    System.err.println("Add User '" + args[1] + "' failed!");
                }
            }
            else if (args[0].equals("update"))
            {
                sqlOpen();
                if(updateUser(args[1],args[2]))
                {
                    System.out.println("User '" + args[1] + "' updated.");
                }
                else {
                    System.err.println("Update User '" + args[1] + "' failed!");
                }
            }
        }
        else {
            help();
        }

        sqlClose();
        closeSQLConDiscon();
        System.exit(exitCode);
    }

    private static void help() {
        System.out.println(
                  "Copyright (c) 2018 Georg Schmidt\n"
                + "GPL 3.0: WITHOUT ANY WARRANTY\n"
                + "Thanks to org.xerial.sqlite-jdbc: Apache License, Version 2.0\n\n"
                + "# Add a user:\n"
                + "xyz.jar add <username> <password>\n\n"
                + "# Update a user:\n"
                + "xyz.jar update <username> <password>\n\n"
                + "# Login:\n"
                + "xyz.jar login\n\n"
                + "# Connect history:\n"
                + "xyz.jar history\n\n"
                + "# Connect to VPN\n"
                + "xyz.jar connect\n\n"
                + "# Disconnect to VPN\n"
                + "xyz.jar disconnect\n\n"
                + "# Delete a user:\n"
                + "xyz.jar update <username> <random data (size 22+)>\n"
        );
    }

    public static boolean sqlOpen() {
        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:" + DB_FILE);
            c.setAutoCommit(true);
        } catch ( Exception e ) {
            e.printStackTrace();
           return false;
        }
//        System.out.println("Opened database successfully");
        return true;
    }

    public static boolean sqlClose() {
        if(c == null)
            return true;

        try {
            c.close();
        } catch ( Exception e ) {
            e.printStackTrace();
            return false;
        }
//        System.out.println("Closed database successfully");
        return true;
    }


    public static boolean sqlSetup() {
        try {
            Statement stmt = c.createStatement();
            String sql = "CREATE TABLE IF NOT EXISTS USER " +
                    "(USERNAME       TEXT    NOT NULL, " +
                    " PASSWORD       TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();

            stmt = c.createStatement();
            String index = "CREATE UNIQUE INDEX idx_USER ON USER (USERNAME);";
            stmt.executeUpdate(index);
            stmt.close();

            stmt = c.createStatement();
            index = "CREATE UNIQUE INDEX idx_PASSWORD ON USER (PASSWORD);";
            stmt.executeUpdate(index);
            stmt.close();
        } catch ( Exception e ) {
            e.printStackTrace();
            return false;
        }
//        System.out.println("Table created successfully");
        return true;
    }

    public static boolean insertUser(String username, String password) {

        String sql = "INSERT INTO USER (USERNAME,PASSWORD) VALUES (?, ?)";
        try {
            PreparedStatement pstmt = c.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.setString(2, bcrypt.encode(password));
            pstmt.executeUpdate();
            pstmt.close();
            return true;
        }catch (SQLException e)
        {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean loginUser(String username, String password) {

        try {
            String sql = "SELECT USERNAME,PASSWORD FROM USER WHERE USERNAME = ?";
            PreparedStatement pstmt = c.prepareStatement(sql);
            pstmt.setString(1, username);
            ResultSet res = pstmt.executeQuery();

            boolean exit = !res.isClosed() && res.next() && res.getString(1).equals(username) &&
                           bcrypt.matches(password, res.getString(2));
            pstmt.close();
            return exit;
        }catch (SQLException e)
        {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean updateUser(String username, String password) {

        try {
            // String sql = "UPDATE USER SET PASSWORD = ? WHERE USERNAME = ?";
            String sql = "INSERT OR REPLACE INTO USER (USERNAME,PASSWORD) VALUES (?, ?)";
            PreparedStatement pstmt = c.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.setString(2, bcrypt.encode(password));
            pstmt.executeUpdate();
            pstmt.close();
            return true;
        }catch (SQLException e)
        {
            return false;
        }
    }

    public static String listUser() {

        StringBuilder sb = new StringBuilder();

        try {
            String sql = "SELECT USERNAME FROM USER";
            Statement stmt = c.createStatement();
            ResultSet res = stmt.executeQuery(sql);

            while(res.next())
            {
                sb.append(res.getString(1)).append("\n");
            }
            int l = sb.length();
            if(l == 0)
            {
                sb.append("No entries!");
            }
            else {
                sb.setLength(l - 1);
            }

            stmt.close();
            return sb.toString();
        }catch (SQLException e)
        {
            e.printStackTrace();
            return "";
        }
    }
}
