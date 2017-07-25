package com.bakkenbaeck.token.headless.db;

import java.util.LinkedList;
import java.util.List;

import org.postgresql.ds.PGPoolingDataSource;
import com.bakkenbaeck.token.headless.signal.ContactInfo;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class PostgresContactStore implements ContactStore {

    private PGPoolingDataSource pool;

    public PostgresContactStore(PGPoolingDataSource pool) {
        this.pool = pool;
    }

    public void updateContact(ContactInfo contact) {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            conn = this.pool.getConnection();
            st = conn.prepareStatement("INSERT INTO contacts_store (number, name, color) VALUES (?, ?, ?) ON CONFLICT (number) DO UPDATE SET name = EXCLUDED.name, color = EXCLUDED.color;");
            st.setString(1, contact.number);
            st.setString(2, contact.name);
            st.setString(3, contact.color);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
            if (conn != null) {
                try { conn.close(); } catch (SQLException e) {}
            }
        }
    }

    public ContactInfo getContact(String number) {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            conn = this.pool.getConnection();
            st = conn.prepareStatement("SELECT * FROM contacts_store WHERE number = ? LIMIT 1");
            st.setString(1, number);
            rs = st.executeQuery();
            if (rs.next()) {
                ContactInfo contact = new ContactInfo();
                contact.name = rs.getString("name");
                contact.number = rs.getString("number");
                contact.color = rs.getString("color");
                return contact;
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
            if (conn != null) {
                try { conn.close(); } catch (SQLException e) {}
            }
        }
    }

    public List<ContactInfo> getContacts() {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        try {
            conn = this.pool.getConnection();
            st = conn.prepareStatement("SELECT * FROM contacts_store");
            rs = st.executeQuery();
            List<ContactInfo> contacts = new LinkedList<>();
            while (rs.next()) {
                ContactInfo contact = new ContactInfo();
                contact.name = rs.getString("name");
                contact.number = rs.getString("number");
                contact.color = rs.getString("color");
                contacts.add(contact);
            }
            return contacts;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {}
            }
            if (st != null) {
                try { st.close(); } catch (SQLException e) {}
            }
            if (conn != null) {
                try { conn.close(); } catch (SQLException e) {}
            }
        }
    }
}
