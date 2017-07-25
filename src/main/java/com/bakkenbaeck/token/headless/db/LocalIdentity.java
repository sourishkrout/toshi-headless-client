package com.bakkenbaeck.token.headless.db;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public class LocalIdentity {

    private String toshiId;
    private int deviceId;
    private String password;
    private byte[] signalingKey;
    private IdentityKeyPair identityKeyPair;
    private int registrationId;
    private int preKeyIdOffset;
    private int nextSignedPreKeyId;
    private boolean registered;

    public LocalIdentity(String toshiId, int deviceId, String password, IdentityKeyPair identityKeyPair,
                         int registrationId, byte[] signalingKey, int preKeyIdOffset, int nextSignedPreKeyId, boolean registered) {
        this.toshiId = toshiId;
        this.deviceId = deviceId;
        this.password = password;
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
        this.signalingKey = signalingKey;
        this.preKeyIdOffset = preKeyIdOffset;
        this.nextSignedPreKeyId = nextSignedPreKeyId;
        this.registered = registered;
    }

    public LocalIdentity(String toshiId, String password, IdentityKeyPair identityKey,
                         int registrationId, byte[] signalingKey) {
        this(toshiId, SignalServiceAddress.DEFAULT_DEVICE_ID, password, identityKey, registrationId, signalingKey, 0, 0, false);
    }

    public LocalIdentity(String toshiId, String password, IdentityKeyPair identityKey,
                         int registrationId, byte[] signalingKey, int preKeyIdOffset, int nextSignedPreKeyId) {
        this(toshiId, SignalServiceAddress.DEFAULT_DEVICE_ID, password, identityKey, registrationId, signalingKey, preKeyIdOffset, nextSignedPreKeyId, false);
    }

    public LocalIdentity(String toshiId, int deviceId, String password, IdentityKeyPair identityKey,
                         int registrationId, byte[] signalingKey, int preKeyIdOffset, int nextSignedPreKeyId) {
        this(toshiId, deviceId, password, identityKey, registrationId, signalingKey, preKeyIdOffset, nextSignedPreKeyId, false);
    }

    public String getToshiId() {
        return toshiId;
    }

    public int getDeviceId() {
        return deviceId;
    }

    public String getPassword() {
        return password;
    }

    public byte[] getSignalingKey() {
        return signalingKey;
    }

    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    public int getRegistrationId() {
        return registrationId;
    }

    public int getPreKeyIdOffset() {
        return preKeyIdOffset;
    }

    public int getNextSignedPreKeyId() {
        return nextSignedPreKeyId;
    }

    public boolean isRegistered() {
        return registered;
    }

    public void setToshiId(String toshiId) {
        this.toshiId = toshiId;
    }

    public void setDeviceId(int deviceId) {
        this.deviceId = deviceId;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setSignalingKey(byte[] signalingKey) {
        this.signalingKey = signalingKey;
    }

    public void setIdentityKeypair(IdentityKeyPair identityKeyPair) {
        this.identityKeyPair = identityKeyPair;
    }

    public void setRegistrationId(int registrationId) {
        this.registrationId = registrationId;
    }

    public void setPreKeyIdOffset(int preKeyIdOffset) {
        this.preKeyIdOffset = preKeyIdOffset;
    }

    public void setNextSignedPreKeyId(int nextSignedPreKeyId) {
        this.nextSignedPreKeyId = nextSignedPreKeyId;
    }

    public void setRegistered(boolean registered) {
        this.registered = registered;
    }
}
