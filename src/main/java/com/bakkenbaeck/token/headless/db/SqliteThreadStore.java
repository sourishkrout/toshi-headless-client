package com.bakkenbaeck.token.headless.db;

import java.util.LinkedList;
import java.util.List;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.bakkenbaeck.token.headless.signal.ThreadInfo;

public class SqliteThreadStore implements ThreadStore {

    private Connection conn;

    public SqliteThreadStore(Connection conn) {
        this.conn = conn;
    }

    public void updateThread(ThreadInfo thread) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("INSERT OR REPLACE INTO thread_store (thread_id, message_expiration_time) VALUES (?, ?) ON CONFLICT (thread_id);");
            st.setString(1, thread.id);
            st.setInt(2, thread.messageExpirationTime);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    public ThreadInfo getThread(String id) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM thread_store WHERE thread_id = ? LIMIT 1");
            st.setString(1, id);
            rs = st.executeQuery();
            if (rs.next()) {
                ThreadInfo thread = new ThreadInfo();
                thread.id = rs.getString("thread_id");
                thread.messageExpirationTime = rs.getInt("message_expiration_time");
                return thread;
            }
            return null;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {}
            }
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    public List<ThreadInfo> getThreads() {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM thread_store");
            rs = st.executeQuery();
            List<ThreadInfo> threads = new LinkedList<>();
            while (rs.next()) {
                ThreadInfo thread = new ThreadInfo();
                thread.id = rs.getString("thread_id");
                thread.messageExpirationTime = rs.getInt("message_expiration_time");
                threads.add(thread);
            }
            return threads;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {}
            }
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

}
