package com.bakkenbaeck.token.headless.db;

import com.bakkenbaeck.token.headless.signal.ContactInfo;
import java.util.List;

public interface ContactStore {
    public void updateContact(ContactInfo thread);
    public ContactInfo getContact(String id);
    public List<ContactInfo> getContacts();
}
