package com.bakkenbaeck.token.headless.db;

import com.bakkenbaeck.token.headless.PostgresConfiguration;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.IdentityKeyPair;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.postgresql.ds.PGPoolingDataSource;

import java.io.IOException;
import java.sql.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.bakkenbaeck.token.headless.signal.Base64;

public class PostgresStore implements Store {

    private PGPoolingDataSource pool;

    private LocalIdentityStore localIdStore;
    private SignalProtocolStore signalProtocolStore;
    private ThreadStore threadStore;
    private ContactStore contactStore;
    private GroupStore groupStore;

    public PostgresStore(PostgresConfiguration config, String schema) {
        this.pool = new PGPoolingDataSource();
        this.pool.setUrl(config.getJdbcUrl());
        this.pool.setUser(config.getUsername());
        this.pool.setPassword(config.getPassword());
        this.pool.setCurrentSchema(schema);
    }

    public LocalIdentityStore getLocalIdentityStore() {
        if (this.localIdStore == null) {
            this.localIdStore = new PostgresLocalIdentityStore(this.pool);
        }
        return this.localIdStore;
    }

    public SignalProtocolStore getSignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
        if (this.signalProtocolStore == null) {
            this.signalProtocolStore = new PostgresSignalProtocolStore(this.pool, identityKeyPair, registrationId);
        }
        return this.signalProtocolStore;
    }
    public ThreadStore getThreadStore() {
        if (this.threadStore == null) {
            this.threadStore = new PostgresThreadStore(this.pool);
        }
        return this.threadStore;
    }

    public ContactStore getContactStore() {
        if (this.contactStore == null) {
            this.contactStore = new PostgresContactStore(this.pool);
        }
        return this.contactStore;
    }

    public GroupStore getGroupStore() {
        if (this.groupStore == null) {
            this.groupStore = new PostgresGroupStore(this.pool);
        }
        return this.groupStore;
    }

    public void migrateLegacyConfigs() {
        // migrate old massive json tables into new format
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            conn = this.pool.getConnection();
            conn.setAutoCommit(false);

            // check if the old signal_store schema still exists
            st = conn.prepareStatement("SELECT EXISTS ( SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ? );");
            st.setString(1, "public");
            st.setString(2, "signal_store");
            rs = st.executeQuery();
            boolean migratePublicSignalStore = rs.next() && rs.getBoolean("exists");
            rs.close();
            st.close();
            if (migratePublicSignalStore) {

                st = conn.prepareStatement("SELECT * FROM public.signal_store");
                rs = st.executeQuery();
                Map<String, String> oldusers = new HashMap<>();
                while (rs.next()) {
                    String eth_address = rs.getString("eth_address");
                    String json = rs.getString("data");
                    oldusers.put(eth_address, json);
                }
                rs.close();
                st.close();

                for (Map.Entry<String, String> entry : oldusers.entrySet()) {
                    String eth_address = entry.getKey();
                    System.out.println("Migrating user: " + eth_address);
                    String json = entry.getValue();
                    ObjectMapper jsonProcessor = new ObjectMapper();
                    JsonNode rootNode = jsonProcessor.readTree(json);

                    // get local id details
                    int deviceId = rootNode.get("deviceId").asInt();
                    String username = rootNode.get("username").asText();
                    String password = rootNode.get("password").asText();
                    String signalingKeyBase64 = rootNode.get("signalingKey").asText();
                    int nextSignedPreKeyId = rootNode.get("nextSignedPreKeyId").asInt();
                    int preKeyIdOffset = rootNode.get("preKeyIdOffset").asInt();
                    boolean registered = rootNode.get("registered").asBoolean();
                    JsonNode axolotlStore = rootNode.get("axolotlStore");
                    JsonNode identityKeyStore = axolotlStore.get("identityKeyStore");
                    String identityKeyBase64 = identityKeyStore.get("identityKey").asText();
                    int registrationId = identityKeyStore.get("registrationId").asInt();

                    st = conn.prepareStatement("INSERT INTO development.local_identities (eth_address, device_id, password, identity_key, registration_id, signaling_key, prekey_id_offset, next_signed_prekey_id, registered) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    st.setString(1, eth_address);
                    st.setInt(2, deviceId);
                    st.setString(3, password);
                    st.setBytes(4, Base64.decode(identityKeyBase64));
                    st.setInt(5, registrationId);
                    st.setBytes(6, Base64.decode(signalingKeyBase64));
                    st.setInt(7, preKeyIdOffset);
                    st.setInt(8, nextSignedPreKeyId);
                    st.setBoolean(9, registered);
                    st.execute();

                    // save identity store data
                    JsonNode trustedKeys = identityKeyStore.get("trustedKeys");
                    for (final JsonNode keyNode : trustedKeys) {
                        st = conn.prepareStatement("INSERT INTO development.signal_identity_store (name, device_id, identity_key) VALUES (?, ?, ?) ON CONFLICT (name, device_id) DO NOTHING");
                        st.setString(1, keyNode.get("name").asText());
                        st.setInt(2, 1); // NOTE: only default node in old store
                        st.setBytes(3, Base64.decode(keyNode.get("identityKey").asText()));
                        st.execute();
                        st.close();
                    }

                    // save prekey store data
                    JsonNode preKeys = axolotlStore.get("preKeys");
                    for (final JsonNode keyNode : preKeys) {
                        st = conn.prepareStatement("INSERT INTO development.signal_prekey_store (prekey_id, record) VALUES (?, ?) ON CONFLICT (prekey_id) DO NOTHING;");
                        st.setInt(1, keyNode.get("id").asInt());
                        st.setBytes(2, Base64.decode(keyNode.get("record").asText()));
                        st.execute();
                        st.close();
                    }

                    // save signed prekey store
                    JsonNode signedPreKeys = axolotlStore.get("signedPreKeyStore");
                    for (final JsonNode keyNode : signedPreKeys) {
                        st = conn.prepareStatement("INSERT INTO development.signal_signed_prekey_store (signed_prekey_id, record) VALUES (?, ?) ON CONFLICT (signed_prekey_id) DO NOTHING;");
                        st.setInt(1, keyNode.get("id").asInt());
                        st.setBytes(2, Base64.decode(keyNode.get("record").asText()));
                        st.execute();
                        st.close();
                    }

                    // save session store data
                    JsonNode sessions = axolotlStore.get("sessionStore");
                    for (final JsonNode keyNode : sessions) {
                        st = conn.prepareStatement("INSERT INTO development.signal_session_store (name, device_id, record) VALUES (?, ?, ?) ON CONFLICT (name, device_id) DO UPDATE SET record = EXCLUDED.record;");
                        st.setString(1, keyNode.get("name").asText());
                        st.setInt(2, keyNode.get("deviceId").asInt());
                        st.setBytes(3, Base64.decode(keyNode.get("record").asText()));
                        st.execute();
                        st.close();
                    }

                    st = conn.prepareStatement("DELETE FROM public.signal_store WHERE eth_address = ?");
                    st.setString(1, eth_address);
                    st.execute();
                    st.close();
                }
                conn.commit();
            }

            // check if there is data in the public schema that needs moving
            st = conn.prepareStatement("SELECT EXISTS ( SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ? );");
            st.setString(1, "public");
            st.setString(2, "bot_sessions");
            rs = st.executeQuery();
            boolean migratePublicTables = rs.next() && rs.getBoolean("exists");
            rs.close();
            st.close();

            if (migratePublicTables) {
                List<String> tables = Arrays.asList("local_identities", "signal_identity_store", "signal_prekey_store", "signal_session_store", "signal_signed_prekey_store", "contacts_store", "thread_store", "group_store", "group_members_store");
                for (String table : tables) {
                    st = conn.prepareStatement("INSERT INTO development." + table + " SELECT * FROM public." + table);
                    st.executeUpdate();
                    st.close();

                    st = conn.prepareStatement("DELETE FROM public." + table);
                    st.executeUpdate();
                    st.close();
                }
            }

        } catch (SQLException|IOException e) {
            // user isn't registered
            System.out.println("Error migrating old user");
            try { conn.rollback(); } catch (SQLException e2) {}
            throw new RuntimeException(e);
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {}
            }
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
            if (conn != null) {
                try {
                    conn.setAutoCommit(true);
                    conn.close();
                } catch (SQLException e) {}
            }
        }

    }

}
