package com.bakkenbaeck.token.headless.db;

import java.util.List;
import java.util.Collection;
import java.util.HashSet;
import java.util.HashMap;
import java.util.ArrayList;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.bakkenbaeck.token.headless.signal.GroupInfo;

public class SqliteGroupStore implements GroupStore {

    private Connection conn;

    public SqliteGroupStore(Connection conn) {
        this.conn = conn;
    }

    public void updateGroup(GroupInfo group) {
        // TODO: maybe Base64.encodeBytes
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            conn.setAutoCommit(false);
            st = conn.prepareStatement("INSERT OR REPLACE INTO group_store (group_id, name, avatar_id, active) VALUES (?, ?, ?, ?);");
            st.setBytes(1, group.groupId);
            st.setString(2, group.name);
            st.setLong(3, group.getAvatarId());
            st.setBoolean(4, group.active);
            st.executeUpdate();
            st.close();
            // members
            st = conn.prepareStatement("INSERT OR REPLACE INTO group_members_store (group_id, number) VALUES (?, ?) ON CONFLICT (group_id, number);");
            for (String member: group.members) {
                st.setBytes(1, group.groupId);
                st.setString(2, member);
                st.addBatch();
            }
            st.executeBatch();
            conn.commit();
        } catch (SQLException e) {
            try { conn.rollback(); } catch (SQLException e2) {}
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
            if (conn != null) {
                try {
                    conn.setAutoCommit(true);
                } catch (SQLException e) {}
            }
        }
    }

    public GroupInfo getGroup(byte[] groupId) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM group_store WHERE group_id = ? LIMIT 1");
            st.setBytes(1, groupId);
            rs = st.executeQuery();
            if (!rs.next()) {
                return null;
            }
            String name = rs.getString("name");
            long avatarId = rs.getLong("avatar_id");
            rs.close();
            st.close();
            st = conn.prepareStatement("SELECT * FROM group_member_store WHERE group_id = ?");
            st.setBytes(1, groupId);
            rs = st.executeQuery();
            Collection<String> members = new HashSet<>();
            while (rs.next()) {
                members.add(rs.getString("number"));
            }
            return new GroupInfo(groupId, name, members, avatarId);
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

    public List<GroupInfo> getGroups() {

        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            HashMap<byte[],GroupInfo> groups = new HashMap<>();
            st = conn.prepareStatement("SELECT * FROM group_store");
            rs = st.executeQuery();
            while (rs.next()) {
                byte[] groupId = rs.getBytes("group_id");
                String name = rs.getString("name");
                long avatarId = rs.getLong("avatar_id");
                Collection<String> members = new HashSet<>();
                groups.put(groupId, new GroupInfo(groupId, name, members, avatarId));
            }
            rs.close();
            st.close();
            st = conn.prepareStatement("SELECT * FROM group_member_store");
            rs = st.executeQuery();
            while (rs.next()) {
                GroupInfo g = groups.get(rs.getBytes("group_id"));
                if (g != null) {
                    g.members.add(rs.getString("number"));
                }
            }

            return new ArrayList<>(groups.values());
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
