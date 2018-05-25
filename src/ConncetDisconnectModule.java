import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.*;
import java.util.Map;

public class ConncetDisconnectModule {

    private static String DB_FILE_CON_DISCON;
    private static Connection cCD = null;

    static {
        try {
            DB_FILE_CON_DISCON = URLDecoder.decode(new File(ConncetDisconnectModule.class.getProtectionDomain().
                    getCodeSource().getLocation().getPath()).getParentFile().getPath(), "UTF-8") + File.separator
                    +  "vpnlog.db";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static boolean openSQLConDiscon() {
        try {
            Class.forName("org.sqlite.JDBC");
            cCD = DriverManager.getConnection("jdbc:sqlite:" + DB_FILE_CON_DISCON);
            cCD.setAutoCommit(true);
        } catch ( Exception e ) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean closeSQLConDiscon() {

        if(cCD == null)
            return true;

        try {
            cCD.close();
        } catch ( Exception e ) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean setupSQLConDiscon() {

        // TODO: Change file permissions to 666

        try {
            Statement stmt = cCD.createStatement();
            String sql = "CREATE TABLE IF NOT EXISTS CONNECT " +
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

            stmt = cCD.createStatement();
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

    public static boolean connect(Map<String, String> env) {

        String sql = "INSERT INTO CONNECT (username, common_name, trusted_ip, trusted_ip6, trusted_port," +
                " ifconfig_pool_remote_ip,remote_port_1, time_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            PreparedStatement pstmt = cCD.prepareStatement(sql);
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
            PreparedStatement pstmt = cCD.prepareStatement(sql);
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

    public static String history() {

        StringBuilder sb = new StringBuilder();

        try {
            String sql = "SELECT * FROM CONNECT";
            Statement stmt = cCD.createStatement();
            ResultSet res = stmt.executeQuery(sql);

            sql = "SELECT * FROM DISCONNECT";
            Statement stmtD = cCD.createStatement();
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
}
