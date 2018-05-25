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


public class OpenVPN {

    private static String DB_FILE;

    static {
        try {
            DB_FILE = URLDecoder.decode(new File(OpenVPN.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParentFile().getPath(), "UTF-8") + File.separator +  "vpnuser.db";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private static Connection c = null;
    private static BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

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

            stmt = c.createStatement();
            sql = "CREATE TABLE IF NOT EXISTS CONNECT " +
                    "(username       TEXT    NOT NULL, " +
                    " common_name    TEXT    NOT NULL, " +
                    " trusted_ip     TEXT    NULL, " +
                    " trusted_ip6    TEXT    NULL, " +
                    " trusted_port   TEXT    NOT NULL, " +
                    " ifconfig_pool_remote_ip  TEXT    NOT NULL, " +
                    " remote_port_1  TEXT    NOT NULL, " +
                    " time_unix      TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();

            stmt = c.createStatement();
            sql = "CREATE TABLE IF NOT EXISTS DISCONNECT " +
                    "(username       TEXT    NOT NULL, " +
                    " common_name    TEXT    NOT NULL, " +
                    " trusted_ip     TEXT    NULL, " +
                    " trusted_ip6    TEXT    NULL, " +
                    " trusted_port   TEXT    NOT NULL, " +
                    " ifconfig_pool_remote_ip  TEXT    NOT NULL, " +
                    " remote_port_1  TEXT    NOT NULL, " +
                    " bytes_received TEXT    NULL, " +
                    " bytes_sent     TEXT    NULL, " +
                    " time_duration  TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
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

    public static boolean connect(Map<String, String> env) {

        String sql = "INSERT INTO CONNECT (username, common_name, trusted_ip, trusted_ip6, trusted_port," +
                " ifconfig_pool_remote_ip,remote_port_1, time_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            PreparedStatement pstmt = c.prepareStatement(sql);
            pstmt.setString(1, env.getOrDefault("username","failed"));
            pstmt.setString(2, env.getOrDefault("common_name","failed"));
            pstmt.setString(3, env.getOrDefault("trusted_ip","no IPv4"));
            pstmt.setString(4, env.getOrDefault("trusted_ip6","no IPv6"));
            pstmt.setString(5, env.getOrDefault("trusted_port","failed"));
            pstmt.setString(6, env.getOrDefault("ifconfig_pool_remote_ip","failed"));
            pstmt.setString(7, env.getOrDefault("remote_port_1","failed"));
            pstmt.setString(8, env.getOrDefault("time_unix","failed"));
            pstmt.executeUpdate();
            pstmt.close();
            return true;
        }catch (SQLException e)
        {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean disconnect(Map<String, String> env) {

        String sql = "INSERT INTO DISCONNECT (username, common_name, trusted_ip, trusted_ip6, trusted_port," +
                " ifconfig_pool_remote_ip, remote_port_1, bytes_received, bytes_sent, time_duration)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            PreparedStatement pstmt = c.prepareStatement(sql);
            pstmt.setString(1, env.getOrDefault("username","failed"));
            pstmt.setString(2, env.getOrDefault("common_name","failed"));
            pstmt.setString(3, env.getOrDefault("trusted_ip","no IPv4"));
            pstmt.setString(4, env.getOrDefault("trusted_ip6","no IPv6"));
            pstmt.setString(5, env.getOrDefault("trusted_port","failed"));
            pstmt.setString(6, env.getOrDefault("ifconfig_pool_remote_ip","0"));
            pstmt.setString(7, env.getOrDefault("remote_port_1","0"));
            pstmt.setString(8, env.getOrDefault("bytes_received","failed"));
            pstmt.setString(9, env.getOrDefault("bytes_sent","failed"));
            pstmt.setString(10, env.getOrDefault("time_unix","failed"));
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

    public static String history() {

        StringBuilder sb = new StringBuilder();

        try {
            String sql = "SELECT * FROM CONNECT";
            Statement stmt = c.createStatement();
            ResultSet res = stmt.executeQuery(sql);

            sql = "SELECT * FROM DISCONNECT";
            Statement stmtD = c.createStatement();
            ResultSet resD = stmtD.executeQuery(sql);

            while(res.next())
            {
                sb.append("username\tcommon_name\ttrusted_ip\ttrusted_ip6\ttrusted_port\t" +
                        "ifconfig_pool_remote_ip\tremote_port_1\ttime_unix\n");
                sb.append(res.getString(1)).append("\t")
                        .append(res.getString(2)).append("\t")
                        .append(res.getString(3)).append("\t")
                        .append(res.getString(4)).append("\t")
                        .append(res.getString(5)).append("\t")
                        .append(res.getString(6)).append("\t")
                        .append(res.getString(7)).append("\t")
                        .append(res.getString(8))
                        .append("\n");

                if(resD.next()) {
                    sb.append("username\tcommon_name\ttrusted_ip\ttrusted_ip6\ttrusted_port\tifconfig_pool_remote_ip\t" +
                            "remote_port_1\tbytes_received\tbytes_sent\ttime_duration\n");
                    sb.append(resD.getString(1)).append("\t")
                            .append(resD.getString(2)).append("\t")
                            .append(resD.getString(3)).append("\t")
                            .append(resD.getString(4)).append("\t")
                            .append(resD.getString(5)).append("\t")
                            .append(resD.getString(6)).append("\t")
                            .append(resD.getString(7)).append("\t")
                            .append(resD.getString(8)).append("\t")
                            .append(resD.getString(9)).append("\t")
                            .append(resD.getString(10))
                            .append("\n\n");
                }
            }
            int l = sb.length();
            if(l == 0)
            {
                sb.append("No entries!");
            }
            else {
                sb.setLength(l - 2);
            }

            stmt.close();

            return sb.toString();
        }catch (SQLException e)
        {
            e.printStackTrace();
            return "";
        }
    }


    public static void main(String ... args) {

        int exitCode = -1;

        if(!Files.exists(Paths.get(DB_FILE)))
        {
            sqlOpen();
            sqlSetup();
        }
        else
        {
            sqlOpen();
        }

        if(args.length == 1)
        {
            switch (args[0]) {
                case "list":
                    System.out.println(listUser());
                    break;
                case "log":
                    System.out.println(history());
                    break;
                case "connect":
                    Map<String, String> env = System.getenv();
                    if(connect(env)) {
                        exitCode = 0;
                    }
                    break;
                case "disconnect":
                    Map<String, String> env2 = System.getenv();
                    if(disconnect(env2)) {
                        exitCode = 0;
                    }
                    break;
                default:

                    System.out.println("Copyright (c) 2018 Georg Schmidt");
                    System.out.println("GPL 3.0: WITHOUT ANY WARRANTY");
                    System.out.println("Thanks to org.xerial.sqlite-jdbc: Apache License, Version 2.0\n");
                    System.out.println("# Add a user:");
                    System.out.println("xyz.jar add <username> <password>");
                    System.out.println("# Update a user:");
                    System.out.println("xyz.jar update <username> <password>");
                    System.out.println("# Login:");
                    System.out.println("xyz.jar");
                    System.out.println("# Connect infos:");
                    System.out.println("xyz.jar log");
                    System.out.println("xyz.jar connect");
                    System.out.println("xyz.jar disconnect");
                    break;
            }
        }
        else if(args.length == 3)
        {
            if (args[0].equals("add"))
            {
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
            Map<String, String> env = System.getenv();
            /*
            for (String envName : env.keySet()) {
                System.out.format("%s=%s%n", envName, env.get(envName));
            }
            */

            String username = env.get("username");
            String password = env.get("password");

            if(username != null && password != null && loginUser(username,password))
            {
                exitCode = 0;
            }
            else {
                System.err.println("Login username '" + username + "' failed!");
                exitCode = -1;
            }
        }

        sqlClose();
        System.exit(exitCode);
    }
}
