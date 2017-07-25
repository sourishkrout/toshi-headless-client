package com.bakkenbaeck.token.headless.db;

import org.whispersystems.libsignal.state.SignalProtocolStore;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.io.IOException;

class SqliteSignalProtocolStore implements SignalProtocolStore {

    private IdentityKeyPair identityKeyPair;
    private int localRegistrationId;
    private Connection conn;

    public SqliteSignalProtocolStore(Connection conn, IdentityKeyPair identityKeyPair, int registrationId) {
        this.conn = conn;
        this.identityKeyPair = identityKeyPair;
        this.localRegistrationId = registrationId;
    }

    // Identity key store

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        return localRegistrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {

        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT 1 FROM signal_identity_store WHERE name = ? AND device_id = ?;");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            rs = st.executeQuery();
            boolean updated = rs.next();
            rs.close();
            st.close();
            st = conn.prepareStatement("INSERT OR REPLACE INTO signal_identity_store (name, device_id, identity_key) VALUES (?, ?, ?);");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            st.setBytes(3, identityKey.serialize());
            st.execute();
            return updated;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM signal_identity_store WHERE name = ? AND device_id = ? LIMIT 1");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            rs = st.executeQuery();
            if (rs.next()) {
                try {
                    return identityKey.equals(new IdentityKey(rs.getBytes("identity_key"), 0));
                } catch (InvalidKeyException e) {
                    return false;
                }
            }
            return true;
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

    // Prekey store

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM signal_prekey_store WHERE prekey_id = ? LIMIT 1");
            st.setInt(1, preKeyId);
            rs = st.executeQuery();
            while (rs.next()) {
                return new PreKeyRecord(rs.getBytes("record"));
            }
            return null;
        } catch (SQLException|IOException e) {
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

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("INSERT OR REPLACE INTO signal_prekey_store (prekey_id, record) VALUES (?, ?);");
            st.setInt(1, preKeyId);
            st.setBytes(2, record.serialize());
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT 1 FROM signal_prekey_store WHERE prekey_id = ? LIMIT 1");
            st.setInt(1, preKeyId);
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

    @Override
    public void removePreKey(int preKeyId) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("DELETE FROM signal_prekey_store WHERE prekey_id = ?");
            st.setInt(1, preKeyId);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    // SESSION Store

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM signal_session_store WHERE name = ? AND device_id = ? LIMIT 1");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            rs = st.executeQuery();
            while (rs.next()) {
                byte[] record = rs.getBytes("record");
                return new SessionRecord(record);
            }
            return new SessionRecord();
        } catch (SQLException|IOException e) {
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

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT device_id FROM signal_session_store WHERE name = ? AND device_id != 1");
            st.setString(1, name);
            rs = st.executeQuery();
            List<Integer> results = new LinkedList<>();
            while (rs.next()) {
                results.add(rs.getInt("device_id"));
            }
            return results;
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

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("INSERT OR REPLACE INTO signal_session_store (name, device_id, record) VALUES (?, ?, ?);");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            st.setBytes(3, record.serialize());
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT 1 FROM signal_session_store WHERE name = ? AND device_id = ?");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
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

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("DELETE FROM signal_session_store WHERE name = ? AND device_id = ?");
            st.setString(1, address.getName());
            st.setInt(2, address.getDeviceId());
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    @Override
    public void deleteAllSessions(String name) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("DELETE FROM signal_session_store WHERE name = ?");
            st.setString(1, name);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    // Signed prekey store

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM signal_signed_prekey_store WHERE signed_prekey_id = ? LIMIT 1");
            st.setInt(1, signedPreKeyId);
            rs = st.executeQuery();
            while (rs.next()) {
                return new SignedPreKeyRecord(rs.getBytes("record"));
            }
            return null;
        } catch (SQLException|IOException e) {
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

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT * FROM signal_signed_prekey_store");
            rs = st.executeQuery();
            List<SignedPreKeyRecord> results = new LinkedList<>();
            while (rs.next()) {
                byte[] record = rs.getBytes("record");
                results.add(new SignedPreKeyRecord(record));
            }
            return results;
        } catch (SQLException|IOException e) {
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

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("INSERT OR REPLACE INTO signal_signed_prekey_store (signed_prekey_id, record) VALUES (?, ?);");
            st.setInt(1, signedPreKeyId);
            st.setBytes(2, record.serialize());
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            st = conn.prepareStatement("SELECT 1 FROM signal_signed_prekey_store WHERE signed_prekey_id = ? LIMIT 1");
            st.setInt(1, signedPreKeyId);
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

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        PreparedStatement st = null;
        try {
            st = conn.prepareStatement("DELETE FROM signal_signed_prekey_store WHERE signed_prekey_id = ?");
            st.setInt(1, signedPreKeyId);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
        }
    }
}
