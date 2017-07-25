package com.bakkenbaeck.token.headless.db;

import com.bakkenbaeck.token.headless.SqliteConfiguration;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.IdentityKeyPair;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import java.io.IOException;
import java.sql.*;



import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class SqliteStore implements Store {

    private Connection conn;
    SqliteConfiguration config;

    private LocalIdentityStore localIdStore;
    private SignalProtocolStore signalProtocolStore;
    private ThreadStore threadStore;
    private ContactStore contactStore;
    private GroupStore groupStore;

    public SqliteStore(SqliteConfiguration config) {
        try {
            this.config = config;
            if (config.getJdbcUrl().isEmpty()) {
                throw new SQLException("Database credentials missing");
            }

            Class.forName("org.sqlite.JDBC");
            this.conn = DriverManager.getConnection(this.config.getJdbcUrl());
        } catch (SQLException|ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public LocalIdentityStore getLocalIdentityStore() {
        if (this.localIdStore == null) {
            this.localIdStore = new SqliteLocalIdentityStore(this.conn);
        }
        return this.localIdStore;
    }

    public SignalProtocolStore getSignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
        if (this.signalProtocolStore == null) {
            this.signalProtocolStore = new SqliteSignalProtocolStore(this.conn, identityKeyPair, registrationId);
        }
        return this.signalProtocolStore;
    }
    public ThreadStore getThreadStore() {
        if (this.threadStore == null) {
            this.threadStore = new SqliteThreadStore(this.conn);
        }
        return this.threadStore;
    }

    public ContactStore getContactStore() {
        if (this.contactStore == null) {
            this.contactStore = new SqliteContactStore(this.conn);
        }
        return this.contactStore;
    }

    public GroupStore getGroupStore() {
        if (this.groupStore == null) {
            this.groupStore = new SqliteGroupStore(this.conn);
        }
        return this.groupStore;
    }

     public void migrateLegacyConfigs() {
         // nothing to do here yet as no one should have used sqlite before this
     }

    public void executeResourceScript(String resourceFilename) {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resourceFilename);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {

            // TODO: must be a nicer way of doing this!
            ArrayList<String> sqls = new ArrayList<String>();
            String insql = "";
            String line = null;
            while ((line = reader.readLine()) != null) {
                insql += line + "\n";
                if (line.endsWith(";")) {
                    sqls.add(insql);
                    insql = "";
                }
            }
            for (String sql: sqls) {
                PreparedStatement st = conn.prepareStatement(sql);
                boolean results = st.execute();
                while (results) {
                    results = st.getMoreResults();
                }
                st.close();
            }

        } catch (IOException x) {
            x.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}
