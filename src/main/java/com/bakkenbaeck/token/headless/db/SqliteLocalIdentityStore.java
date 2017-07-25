package com.bakkenbaeck.token.headless.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;

public class SqliteLocalIdentityStore implements LocalIdentityStore {

    private Connection conn;

    public SqliteLocalIdentityStore(Connection conn) {
        this.conn = conn;
    }

    public LocalIdentity loadLocalIdentity(String toshiId) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM local_identities WHERE eth_address = ? LIMIT 1");
            st.setString(1, toshiId);
            rs = st.executeQuery();
            if (rs.next()) {
                int deviceId = rs.getInt("device_id");
                String password = rs.getString("password");
                byte[] signalingKey = rs.getBytes("signaling_key");
                byte[] identityKeyBytes = rs.getBytes("identity_key");
                IdentityKeyPair identityKey = new IdentityKeyPair(identityKeyBytes);
                int registrationId = rs.getInt("registration_id");
                int preKeyIdOffset = rs.getInt("prekey_id_offset");
                int nextSignedPreKeyId = rs.getInt("next_signed_prekey_id");
                boolean registered = rs.getBoolean("registered");
                return new LocalIdentity(toshiId, deviceId, password, identityKey, registrationId,
                                         signalingKey, preKeyIdOffset, nextSignedPreKeyId, registered);
            } else {
                return null;
            }
        } catch (SQLException|InvalidKeyException e) {
            System.out.println("Unexpected Error loading user");
            e.printStackTrace();
            return null;
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {}
            }
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    public boolean exists(String toshiId) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT 1 FROM local_identities WHERE eth_address = ? LIMIT 1");
            st.setString(1, toshiId);
            rs = st.executeQuery();
            if (rs.next()) {
                return true;
            }
            return false;
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

    public void saveLocalIdentity(LocalIdentity identity) {
        PreparedStatement st = null;
        ResultSet rs = null;
        int userId;
        try {
            st = conn.prepareStatement("INSERT OR REPLACE INTO local_identities (eth_address, device_id, password, identity_key, registration_id, signaling_key, prekey_id_offset, next_signed_prekey_id, registered) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            st.setString(1, identity.getToshiId());
            st.setInt(2, identity.getDeviceId());
            st.setString(3, identity.getPassword());
            st.setBytes(4, identity.getIdentityKeyPair().serialize());
            st.setInt(5, identity.getRegistrationId());
            st.setBytes(6, identity.getSignalingKey());
            st.setInt(7, identity.getPreKeyIdOffset());
            st.setInt(8, identity.getNextSignedPreKeyId());
            st.setBoolean(9, identity.isRegistered());
            st.execute();
        } catch (SQLException e) {
            System.out.println("Unexpected Error saving user");
            e.printStackTrace();
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
