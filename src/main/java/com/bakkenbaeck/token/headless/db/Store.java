package com.bakkenbaeck.token.headless.db;

import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.IdentityKeyPair;

public interface Store {
    public LocalIdentityStore getLocalIdentityStore();
    public SignalProtocolStore getSignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId);
    public ThreadStore getThreadStore();
    public ContactStore getContactStore();
    public GroupStore getGroupStore();

    public void migrateLegacyConfigs();
}
