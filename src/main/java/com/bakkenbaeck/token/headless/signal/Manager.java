/**
 * Copyright (C) 2015 AsamK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.bakkenbaeck.token.headless.signal;

import com.bakkenbaeck.token.crypto.HDWallet;
import com.bakkenbaeck.token.headless.db.Store;
import com.bakkenbaeck.token.headless.db.LocalIdentity;
import com.bakkenbaeck.token.headless.db.GroupStore;
import com.bakkenbaeck.token.headless.db.ThreadStore;
import com.bakkenbaeck.token.headless.db.ContactStore;
import okhttp3.*;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.apache.tika.Tika;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.SignalServiceMessagePipe;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.*;
import org.whispersystems.signalservice.api.messages.multidevice.*;
import org.whispersystems.signalservice.api.push.ContactTokenDetails;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.*;
import org.whispersystems.signalservice.api.util.InvalidNumberException;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos;
import org.whispersystems.signalservice.internal.push.SignalServiceUrl;
import org.whispersystems.signalservice.internal.util.JsonUtil;

import java.io.*;
import java.net.URLDecoder;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static java.nio.file.attribute.PosixFilePermission.*;

public class Manager {
    //TODO: Make this overridable in config file
    private final static boolean autoAcceptKeys = true;

    private final int MAX_ATTACHEMENT_SIZE_BYTES = 1024 * 100;

    private final static Tika tika = new Tika();

    private final String URL;
    private final SignalServiceUrl[] serviceUrls;

    public final static String PROJECT_NAME = Manager.class.getPackage().getImplementationTitle();
    public final static String PROJECT_VERSION = Manager.class.getPackage().getImplementationVersion();
    private final static String USER_AGENT = PROJECT_NAME == null ? null : PROJECT_NAME + " " + PROJECT_VERSION;

    private final static int PREKEY_MINIMUM_COUNT = 20;
    private static final int PREKEY_BATCH_SIZE = 100;

    private final String settingsPath;
    private final String dataPath;
    private final String attachmentsPath;
    private final String avatarsPath;

    private FileLock lock;

    private HDWallet wallet;
    private Store storage;
    private LocalIdentity localIdentity;
    private SignalProtocolStore signalProtocolStore;
    private SignalServiceAccountManager accountManager;
    private GroupStore groupStore;
    private ContactStore contactStore;
    private ThreadStore threadStore;

    public Manager(HDWallet wallet, String settingsPath, String serverUrl, String trustStoreName, Store storage) {

        this.storage = storage;

        URL = serverUrl;
        serviceUrls = new SignalServiceUrl[]{new SignalServiceUrl(URL, new WhisperTrustStore(trustStoreName))};

        this.wallet = wallet;
        this.settingsPath = settingsPath;
        this.dataPath = this.settingsPath + "/data";
        this.attachmentsPath = this.settingsPath + "/attachments";
        this.avatarsPath = this.settingsPath + "/avatars";
        new File(this.dataPath).mkdirs();
        new File(this.attachmentsPath).mkdirs();
        new File(this.avatarsPath).mkdirs();
    }

    private IdentityKey getIdentity() {
        return signalProtocolStore.getIdentityKeyPair().getPublicKey();
    }

    public String getOwnerAddress() {
        if (this.localIdentity != null) {
            return this.localIdentity.getToshiId();
        } else {
            return this.wallet.getOwnerAddress();
        }
    }

    public int getDeviceId() {
        return this.localIdentity.getDeviceId();
    }

    public String getFileName() {
        return dataPath + "/" + wallet.getOwnerAddress();
    }

    private String getMessageCachePath() {
        return this.dataPath + "/" + wallet.getOwnerAddress() + ".d/msg-cache";
    }

    private String getMessageCachePath(String sender) {
        return getMessageCachePath() + "/" + sender.replace("/", "_");
    }

    private File getMessageCacheFile(String sender, long now, long timestamp) throws IOException {
        String cachePath = getMessageCachePath(sender);
        createPrivateDirectories(cachePath);
        return new File(cachePath + "/" + now + "_" + timestamp);
    }

    private static void createPrivateDirectories(String path) throws IOException {
        final Path file = new File(path).toPath();
        try {
            Set<PosixFilePermission> perms = EnumSet.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE);
            Files.createDirectories(file, PosixFilePermissions.asFileAttribute(perms));
        } catch (UnsupportedOperationException e) {
            Files.createDirectories(file);
        }
    }

    private static void createPrivateFile(String path) throws IOException {
        final Path file = new File(path).toPath();
        try {
            Set<PosixFilePermission> perms = EnumSet.of(OWNER_READ, OWNER_WRITE);
            Files.createFile(file, PosixFilePermissions.asFileAttribute(perms));
        } catch (UnsupportedOperationException e) {
            Files.createFile(file);
        }
    }

    public boolean userExists() {
        return storage.getLocalIdentityStore().exists(wallet.getOwnerAddress());
    }

    public boolean userHasKeys() {
        return signalProtocolStore != null;
    }

    public void init() throws IOException {
        this.storage.migrateLegacyConfigs();

        boolean refreshKeys = false;
        // load the identity
        this.localIdentity = this.storage.getLocalIdentityStore().loadLocalIdentity(wallet.getOwnerAddress());
        if (this.localIdentity == null) {
            // if none was loaded, create a new identity
            createNewIdentity();
            refreshKeys = true;
        }

        // set up stores
        groupStore = this.storage.getGroupStore();
        threadStore = this.storage.getThreadStore();
        contactStore = this.storage.getContactStore();
        signalProtocolStore = this.storage.getSignalProtocolStore(this.localIdentity.getIdentityKeyPair(),
                                                                  this.localIdentity.getRegistrationId());

        accountManager = new SignalServiceAccountManager(serviceUrls, localIdentity.getToshiId(),
                                                         this.localIdentity.getPassword(),
                                                         USER_AGENT);

        // do key refresh
        try {
            if (localIdentity.isRegistered()) {
                if (refreshKeys || accountManager.getPreKeysCount() < PREKEY_MINIMUM_COUNT) {
                    refreshPreKeys();
                }
            }
        } catch (AuthorizationFailedException e) {
            System.err.println("Authorization failed, was the number registered elsewhere?");
        }
    }

    public void createNewIdentity() {
        IdentityKeyPair identityKey = KeyHelper.generateIdentityKeyPair();
        int registrationId = KeyHelper.generateRegistrationId(false);
        String password = Util.getSecret(18);
        boolean registered = false;
        String signalingKey = Util.getSecret(52);

        try {
            this.localIdentity = new LocalIdentity(wallet.getOwnerAddress(), password,
                                                   identityKey, registrationId,
                                                   Base64.decode(signalingKey));
        } catch (IOException e) {
            // very unexpected
            System.err.println("Error generating signaling key");
            throw new RuntimeException(e);
        }

        // register user
        try {
            DefaultAccountAttributes accountAttributes = new DefaultAccountAttributes(signalingKey, registrationId, true);
            String json = JsonUtil.toJson(accountAttributes);
            String url = serviceUrls[0].getUrl() + "/v1/accounts/";
            final String timestamp = String.valueOf(System.currentTimeMillis() / 1000);

            final String idAddress = this.localIdentity.getToshiId();
            final int deviceId = this.localIdentity.getDeviceId();

            String verb = "PUT";
            String path = "/v1/accounts/";

            final Keccak.DigestKeccak keccak = new Keccak.Digest256();
            keccak.update(json.getBytes());
            byte[] hash = keccak.digest();
            byte[] encodedHashBytes = Base64.encodeBytesToBytes(hash);
            String encodedHash = new String(encodedHashBytes);
            String payload = verb+"\n"+path+"\n"+timestamp+"\n"+encodedHash;
            final String signature = wallet.signIdentity(payload);

            OkHttpClient client = new OkHttpClient();

            String authheader;
            try {
                if (deviceId == 1) {
                    authheader = "Basic " + Base64.encodeBytes((idAddress + ":" + password).getBytes("UTF-8"));
                } else {
                    authheader = "Basic " + Base64.encodeBytes((idAddress + "." + deviceId + ":" + password).getBytes("UTF-8"));
                }
            } catch (UnsupportedEncodingException e) {
                throw new AssertionError(e);
            }

            Request request = new Request.Builder()
                .url(url)
                .put(RequestBody.create(MediaType.parse("application/json; charset=utf-8"), json))
                .header("Authorization", authheader)
                .header("Token-Timestamp", timestamp)
                .header("Token-Signature", signature)
                .header("Token-ID-Address", idAddress)
                .build();

            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Unable to register user");
        }

        localIdentity.setRegistered(true);
        this.storage.getLocalIdentityStore().saveLocalIdentity(localIdentity);
    }

    public boolean isRegistered() {
        return this.localIdentity != null && this.localIdentity.isRegistered();
    }

    public static Map<String, String> getQueryMap(String query) {
        String[] params = query.split("&");
        Map<String, String> map = new HashMap<>();
        for (String param : params) {
            String name = null;
            try {
                name = URLDecoder.decode(param.split("=")[0], "utf-8");
            } catch (UnsupportedEncodingException e) {
                // Impossible
            }
            String value = null;
            try {
                value = URLDecoder.decode(param.split("=")[1], "utf-8");
            } catch (UnsupportedEncodingException e) {
                // Impossible
            }
            map.put(name, value);
        }
        return map;
    }

    private List<PreKeyRecord> generatePreKeys() {
        List<PreKeyRecord> records = new LinkedList<>();

        int preKeyIdOffset = localIdentity.getPreKeyIdOffset();

        for (int i = 0; i < PREKEY_BATCH_SIZE; i++) {
            int preKeyId = (preKeyIdOffset + i) % Medium.MAX_VALUE;
            ECKeyPair keyPair = Curve.generateKeyPair();
            PreKeyRecord record = new PreKeyRecord(preKeyId, keyPair);

            signalProtocolStore.storePreKey(preKeyId, record);
            records.add(record);
        }

        preKeyIdOffset = (preKeyIdOffset + PREKEY_BATCH_SIZE + 1) % Medium.MAX_VALUE;
        localIdentity.setPreKeyIdOffset(preKeyIdOffset);
        this.storage.getLocalIdentityStore().saveLocalIdentity(localIdentity);

        return records;
    }

    private PreKeyRecord getOrGenerateLastResortPreKey() {
        if (signalProtocolStore.containsPreKey(Medium.MAX_VALUE)) {
            try {
                return signalProtocolStore.loadPreKey(Medium.MAX_VALUE);
            } catch (InvalidKeyIdException e) {
                signalProtocolStore.removePreKey(Medium.MAX_VALUE);
            }
        }

        ECKeyPair keyPair = Curve.generateKeyPair();
        PreKeyRecord record = new PreKeyRecord(Medium.MAX_VALUE, keyPair);

        signalProtocolStore.storePreKey(Medium.MAX_VALUE, record);

        return record;
    }

    private SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair) {
        try {
            ECKeyPair keyPair = Curve.generateKeyPair();
            byte[] signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());
            int nextSignedPreKeyId = localIdentity.getNextSignedPreKeyId();
            SignedPreKeyRecord record = new SignedPreKeyRecord(nextSignedPreKeyId, System.currentTimeMillis(), keyPair, signature);

            signalProtocolStore.storeSignedPreKey(nextSignedPreKeyId, record);
            nextSignedPreKeyId = (nextSignedPreKeyId + 1) % Medium.MAX_VALUE;

            localIdentity.setNextSignedPreKeyId(nextSignedPreKeyId);
            this.storage.getLocalIdentityStore().saveLocalIdentity(localIdentity);

            return record;
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    private void refreshPreKeys() throws IOException {
        List<PreKeyRecord> oneTimePreKeys = generatePreKeys();
        PreKeyRecord lastResortKey = getOrGenerateLastResortPreKey();
        SignedPreKeyRecord signedPreKeyRecord = generateSignedPreKey(signalProtocolStore.getIdentityKeyPair());

        accountManager.setPreKeys(signalProtocolStore.getIdentityKeyPair().getPublicKey(), signedPreKeyRecord, oneTimePreKeys);
    }


    private static List<SignalServiceAttachment> getSignalServiceAttachments(List<String> attachments) throws AttachmentInvalidException {
        List<SignalServiceAttachment> SignalServiceAttachments = null;
        if (attachments != null) {
            SignalServiceAttachments = new ArrayList<>(attachments.size());
            for (String attachment : attachments) {
                try {
                    SignalServiceAttachments.add(createAttachment(new File(attachment)));
                } catch (IOException e) {
                    throw new AttachmentInvalidException(attachment, e);
                }
            }
        }
        return SignalServiceAttachments;
    }

    private static SignalServiceAttachmentStream createAttachment(File attachmentFile) throws IOException {
        InputStream attachmentStream = new FileInputStream(attachmentFile);
        final long attachmentSize = attachmentFile.length();
        String mime = tika.detect(attachmentFile);

        if (mime == null) {
            mime = "application/octet-stream";
        }

        return SignalServiceAttachment.newStreamBuilder()
            .withStream(attachmentStream)
            .withContentType(mime)
            .withLength(attachmentSize)
            .build();
    }

    private Optional<SignalServiceAttachmentStream> createGroupAvatarAttachment(byte[] groupId) throws IOException {
        File file = getGroupAvatarFile(groupId);
        if (!file.exists()) {
            return Optional.absent();
        }

        return Optional.of(createAttachment(file));
    }

    private Optional<SignalServiceAttachmentStream> createContactAvatarAttachment(String number) throws IOException {
        File file = getContactAvatarFile(number);
        if (!file.exists()) {
            return Optional.absent();
        }

        return Optional.of(createAttachment(file));
    }

    private GroupInfo getGroupForSending(byte[] groupId) throws GroupNotFoundException, NotAGroupMemberException {
        GroupInfo g = groupStore.getGroup(groupId);
        if (g == null) {
            throw new GroupNotFoundException(groupId);
        }
        for (String member : g.members) {
            if (member.equals(this.wallet.getOwnerAddress())) {
                return g;
            }
        }
        throw new NotAGroupMemberException(groupId, g.name);
    }


    public void sendGroupMessage(String messageText, List<String> attachments,
                                 byte[] groupId)
            throws IOException, EncapsulatedExceptions, GroupNotFoundException, AttachmentInvalidException, NotAGroupMemberException {
        final SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder().withBody(messageText);
        if (attachments != null) {
            messageBuilder.withAttachments(getSignalServiceAttachments(attachments));
        }
        if (groupId != null) {
            SignalServiceGroup group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.DELIVER)
                    .withId(groupId)
                    .build();
            messageBuilder.asGroupMessage(group);
        }
        ThreadInfo thread = threadStore.getThread(Base64.encodeBytes(groupId));
        if (thread != null) {
            messageBuilder.withExpiration(thread.messageExpirationTime);
        }

        final GroupInfo g = getGroupForSending(groupId);

        // Don't send group message to ourself
        final List<String> membersSend = new ArrayList<>(g.members);
        membersSend.remove(this.wallet.getOwnerAddress());
        sendMessage(messageBuilder, membersSend);
    }

    public void sendQuitGroupMessage(byte[] groupId) throws GroupNotFoundException, IOException, EncapsulatedExceptions, NotAGroupMemberException {
        SignalServiceGroup group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.QUIT)
                .withId(groupId)
                .build();

        SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder()
                .asGroupMessage(group);

        final GroupInfo g = getGroupForSending(groupId);
        g.members.remove(this.wallet.getOwnerAddress());
        groupStore.updateGroup(g);

        sendMessage(messageBuilder, g.members);
    }

    private static String join(CharSequence separator, Iterable<? extends CharSequence> list) {
        StringBuilder buf = new StringBuilder();
        for (CharSequence str : list) {
            if (buf.length() > 0) {
                buf.append(separator);
            }
            buf.append(str);
        }

        return buf.toString();
    }

    public byte[] sendUpdateGroupMessage(byte[] groupId, String name, Collection<String> members, String avatarFile) throws IOException, EncapsulatedExceptions, GroupNotFoundException, AttachmentInvalidException, NotAGroupMemberException {
        GroupInfo g;
        if (groupId == null) {
            // Create new group
            g = new GroupInfo(Util.getSecretBytes(16));
            g.members.add(wallet.getOwnerAddress());
        } else {
            g = getGroupForSending(groupId);
        }

        if (name != null) {
            g.name = name;
        }

        if (members != null) {
            Set<String> newMembers = new HashSet<>();
            for (String member : members) {
                if (g.members.contains(member)) {
                    continue;
                }
                newMembers.add(member);
                g.members.add(member);
            }
            final List<ContactTokenDetails> contacts = accountManager.getContacts(newMembers);
            if (contacts.size() != newMembers.size()) {
                // Some of the new members are not registered on Signal
                for (ContactTokenDetails contact : contacts) {
                    newMembers.remove(contact.getNumber());
                }
                System.err.println("Failed to add members " + join(", ", newMembers) + " to group: Not registered on Signal");
                System.err.println("Aborting…");
                System.exit(1);
            }
        }

        if (avatarFile != null) {
            createPrivateDirectories(avatarsPath);
            File aFile = getGroupAvatarFile(g.groupId);
            Files.copy(Paths.get(avatarFile), aFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        groupStore.updateGroup(g);

        SignalServiceDataMessage.Builder messageBuilder = getGroupUpdateMessageBuilder(g);

        // Don't send group message to ourself
        final List<String> membersSend = new ArrayList<>(g.members);
        membersSend.remove(this.wallet.getOwnerAddress());
        sendMessage(messageBuilder, membersSend);
        return g.groupId;
    }

    private void sendUpdateGroupMessage(byte[] groupId, String recipient) throws IOException, EncapsulatedExceptions, NotAGroupMemberException, GroupNotFoundException, AttachmentInvalidException {
        if (groupId == null) {
            return;
        }
        GroupInfo g = getGroupForSending(groupId);

        if (!g.members.contains(recipient)) {
            return;
        }

        SignalServiceDataMessage.Builder messageBuilder = getGroupUpdateMessageBuilder(g);

        // Send group message only to the recipient who requested it
        final List<String> membersSend = new ArrayList<>();
        membersSend.add(recipient);
        sendMessage(messageBuilder, membersSend);
    }

    private SignalServiceDataMessage.Builder getGroupUpdateMessageBuilder(GroupInfo g) throws AttachmentInvalidException {
        SignalServiceGroup.Builder group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.UPDATE)
                .withId(g.groupId)
                .withName(g.name)
                .withMembers(new ArrayList<>(g.members));

        File aFile = getGroupAvatarFile(g.groupId);
        if (aFile.exists()) {
            try {
                group.withAvatar(createAttachment(aFile));
            } catch (IOException e) {
                throw new AttachmentInvalidException(aFile.toString(), e);
            }
        }

        return SignalServiceDataMessage.newBuilder()
                .asGroupMessage(group.build());
    }

    private void sendGroupInfoRequest(byte[] groupId, String recipient) throws IOException, EncapsulatedExceptions {
        if (groupId == null) {
            return;
        }

        SignalServiceGroup.Builder group = SignalServiceGroup.newBuilder(SignalServiceGroup.Type.REQUEST_INFO)
                .withId(groupId);

        SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder()
                .asGroupMessage(group.build());

        // Send group info request message to the recipient who sent us a message with this groupId
        final List<String> membersSend = new ArrayList<>();
        membersSend.add(recipient);
        sendMessage(messageBuilder, membersSend);
    }


    public void sendMessage(String message, List<String> attachments, String recipient)
            throws EncapsulatedExceptions, AttachmentInvalidException, IOException {
        List<String> recipients = new ArrayList<>(1);
        recipients.add(recipient);
        sendMessage(message, attachments, recipients);
    }


    public void sendMessage(String messageText, List<String> attachments,
                            List<String> recipients)
            throws IOException, EncapsulatedExceptions, AttachmentInvalidException {
        final SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder().withBody(messageText);
        if (attachments != null) {
            messageBuilder.withAttachments(getSignalServiceAttachments(attachments));
        }
        sendMessage(messageBuilder, recipients);
    }


    public void sendEndSessionMessage(List<String> recipients) throws IOException, EncapsulatedExceptions {
        SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder()
                .asEndSessionMessage();

        sendMessage(messageBuilder, recipients);
    }

    private void requestSyncGroups() throws IOException {
        SignalServiceProtos.SyncMessage.Request r = SignalServiceProtos.SyncMessage.Request.newBuilder().setType(SignalServiceProtos.SyncMessage.Request.Type.GROUPS).build();
        SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(r));
        try {
            sendSyncMessage(message);
        } catch (UntrustedIdentityException e) {
            e.printStackTrace();
        }
    }

    private void requestSyncContacts() throws IOException {
        SignalServiceProtos.SyncMessage.Request r = SignalServiceProtos.SyncMessage.Request.newBuilder().setType(SignalServiceProtos.SyncMessage.Request.Type.CONTACTS).build();
        SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(r));
        try {
            sendSyncMessage(message);
        } catch (UntrustedIdentityException e) {
            // TODO: save that this is untrusted?
            e.printStackTrace();
        }
    }

    private void sendSyncMessage(SignalServiceSyncMessage message)
            throws IOException, UntrustedIdentityException {
        SignalServiceMessageSender messageSender = new SignalServiceMessageSender(serviceUrls, localIdentity.getToshiId(), localIdentity.getPassword(), signalProtocolStore, USER_AGENT, Optional.<SignalServiceMessagePipe>absent(), Optional.<SignalServiceMessageSender.EventListener>absent());
        try {
            messageSender.sendMessage(message);
        } catch (UntrustedIdentityException e) {
            // TODO: save that this is untrusted?
            throw e;
        }
    }

    private void sendMessage(SignalServiceDataMessage.Builder messageBuilder, Collection<String> recipients)
            throws EncapsulatedExceptions, IOException {
        Set<SignalServiceAddress> recipientsTS = getSignalServiceAddresses(recipients);
        if (recipientsTS == null) return;

        SignalServiceDataMessage message = null;
        try {
            SignalServiceMessageSender messageSender = new SignalServiceMessageSender(serviceUrls, localIdentity.getToshiId(), localIdentity.getPassword(), signalProtocolStore, USER_AGENT, Optional.<SignalServiceMessagePipe>absent(), Optional.<SignalServiceMessageSender.EventListener>absent());

            message = messageBuilder.build();

            // System.out.println("Sending message: " + message.getBody());
            // for (SignalServiceAddress a : recipientsTS) {
            //     System.out.println("To: " + a.getNumber());
            // }

            if (message.getGroupInfo().isPresent()) {
                try {
                    messageSender.sendMessage(new ArrayList<>(recipientsTS), message);
                } catch (EncapsulatedExceptions encapsulatedExceptions) {
                    for (UntrustedIdentityException e : encapsulatedExceptions.getUntrustedIdentityExceptions()) {
                        // TODO: something?!
                        e.printStackTrace();
                    }
                }
            } else {
                // Send to all individually, so sync messages are sent correctly
                List<UntrustedIdentityException> untrustedIdentities = new LinkedList<>();
                List<UnregisteredUserException> unregisteredUsers = new LinkedList<>();
                List<NetworkFailureException> networkExceptions = new LinkedList<>();
                for (SignalServiceAddress address : recipientsTS) {
                    ThreadInfo thread = threadStore.getThread(address.getNumber());
                    if (thread != null) {
                        messageBuilder.withExpiration(thread.messageExpirationTime);
                    } else {
                        messageBuilder.withExpiration(0);
                    }
                    message = messageBuilder.build();
                    try {
                        messageSender.sendMessage(address, message);
                    } catch (UntrustedIdentityException e) {
                        if (autoAcceptKeys) {
                            // the identity store has been changed to only accept SignalAddress
                            // TODO: multidevice support?
                            signalProtocolStore.saveIdentity(new SignalProtocolAddress(e.getE164Number(), 1), e.getIdentityKey());
                            try {
                                messageSender.sendMessage(address, message);
                            } catch (UntrustedIdentityException eTwo) {
                                System.err.println("UntrustedIdentityException sending message to: " + address.getNumber());
                                untrustedIdentities.add(eTwo);
                            }
                        } else {
                            untrustedIdentities.add(e);
                        }
                    } catch (UnregisteredUserException e) {
                        System.err.println("UnregisteredUserException sending message to: " + address.getNumber());
                        unregisteredUsers.add(e);
                    } catch (PushNetworkException e) {
                        System.err.println("PushNetworkException sending message to: " + address.getNumber());
                        e.printStackTrace();
                        networkExceptions.add(new NetworkFailureException(address.getNumber(), e));
                    }
                }
                if (!untrustedIdentities.isEmpty() || !unregisteredUsers.isEmpty() || !networkExceptions.isEmpty()) {
                    throw new EncapsulatedExceptions(untrustedIdentities, unregisteredUsers, networkExceptions);
                }
            }
        } finally {
            if (message != null && message.isEndSession()) {
                for (SignalServiceAddress recipient : recipientsTS) {
                    handleEndSession(recipient.getNumber());
                }
            }
        }
    }

    private Set<SignalServiceAddress> getSignalServiceAddresses(Collection<String> recipients) {
        Set<SignalServiceAddress> recipientsTS = new HashSet<>(recipients.size());
        for (String recipient : recipients) {
            try {
                recipientsTS.add(getPushAddress(recipient));
            } catch (InvalidNumberException e) {
                System.err.println("Failed to add recipient \"" + recipient + "\": " + e.getMessage());
                System.err.println("Aborting sending.");
                return null;
            }
        }
        return recipientsTS;
    }

    private SignalServiceContent decryptMessage(SignalServiceEnvelope envelope) throws NoSessionException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, InvalidKeyException, InvalidKeyIdException, org.whispersystems.libsignal.UntrustedIdentityException {
        SignalServiceCipher cipher = new SignalServiceCipher(new SignalServiceAddress(wallet.getOwnerAddress()), signalProtocolStore);
        try {
            return cipher.decrypt(envelope);
        } catch (org.whispersystems.libsignal.UntrustedIdentityException e) {
            signalProtocolStore.saveIdentity(new SignalProtocolAddress(e.getName(), 1), e.getUntrustedIdentity());
            return cipher.decrypt(envelope);
        }
    }

    private void handleEndSession(String source) {
        signalProtocolStore.deleteAllSessions(source);
    }

    public interface ReceiveMessageHandler {
        void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent decryptedContent, Throwable e);
    }

    private void handleSignalServiceDataMessage(SignalServiceDataMessage message, boolean isSync, String source, String destination, boolean ignoreAttachments) {
        String threadId;
        if (message.getGroupInfo().isPresent()) {
            SignalServiceGroup groupInfo = message.getGroupInfo().get();
            threadId = Base64.encodeBytes(groupInfo.getGroupId());
            GroupInfo group = groupStore.getGroup(groupInfo.getGroupId());
            switch (groupInfo.getType()) {
                case UPDATE:
                    if (group == null) {
                        group = new GroupInfo(groupInfo.getGroupId());
                    }

                    if (groupInfo.getAvatar().isPresent()) {
                        SignalServiceAttachment avatar = groupInfo.getAvatar().get();
                        if (avatar.isPointer()) {
                            try {
                                retrieveGroupAvatarAttachment(avatar.asPointer(), group.groupId);
                            } catch (IOException | InvalidMessageException e) {
                                System.err.println("Failed to retrieve group avatar (" + avatar.asPointer().getId() + "): " + e.getMessage());
                            }
                        }
                    }

                    if (groupInfo.getName().isPresent()) {
                        group.name = groupInfo.getName().get();
                    }

                    if (groupInfo.getMembers().isPresent()) {
                        group.members.addAll(groupInfo.getMembers().get());
                    }

                    groupStore.updateGroup(group);
                    break;
                case DELIVER:
                    if (group == null) {
                        try {
                            sendGroupInfoRequest(groupInfo.getGroupId(), source);
                        } catch (IOException | EncapsulatedExceptions e) {
                            e.printStackTrace();
                        }
                    }
                    break;
                case QUIT:
                    if (group == null) {
                        try {
                            sendGroupInfoRequest(groupInfo.getGroupId(), source);
                        } catch (IOException | EncapsulatedExceptions e) {
                            e.printStackTrace();
                        }
                    } else {
                        group.members.remove(source);
                        groupStore.updateGroup(group);
                    }
                    break;
                case REQUEST_INFO:
                    if (group != null) {
                        try {
                            sendUpdateGroupMessage(groupInfo.getGroupId(), source);
                        } catch (IOException | EncapsulatedExceptions e) {
                            e.printStackTrace();
                        } catch (NotAGroupMemberException e) {
                            // We have left this group, so don't send a group update message
                        } catch (GroupNotFoundException e) {
                            e.printStackTrace();
                        } catch (AttachmentInvalidException e) {
                            e.printStackTrace();
                        }
                    }
                    break;
            }
        } else {
            if (isSync) {
                threadId = destination;
            } else {
                threadId = source;
            }
        }
        if (message.isEndSession()) {
            handleEndSession(isSync ? destination : source);
        }
        if (message.isExpirationUpdate() || message.getBody().isPresent()) {
            ThreadInfo thread = threadStore.getThread(threadId);
            if (thread == null) {
                thread = new ThreadInfo();
                thread.id = threadId;
            }
            if (thread.messageExpirationTime != message.getExpiresInSeconds()) {
                thread.messageExpirationTime = message.getExpiresInSeconds();
                threadStore.updateThread(thread);
            }
        }
        if (message.getAttachments().isPresent() && !ignoreAttachments) {
            for (SignalServiceAttachment attachment : message.getAttachments().get()) {
                if (attachment.isPointer()) {
                    try {
                        retrieveAttachment(attachment.asPointer());
                    } catch (IOException | InvalidMessageException e) {
                        System.err.println("Failed to retrieve attachment (" + attachment.asPointer().getId() + "): " + e.getMessage());
                    }
                }
            }
        }
    }

    public void retryFailedReceivedMessages(ReceiveMessageHandler handler, boolean ignoreAttachments) {
        final File cachePath = new File(getMessageCachePath());
        if (!cachePath.exists()) {
            return;
        }
        for (final File dir : cachePath.listFiles()) {
            if (!dir.isDirectory()) {
                continue;
            }

            for (final File fileEntry : dir.listFiles()) {
                if (!fileEntry.isFile()) {
                    continue;
                }
                SignalServiceEnvelope envelope;
                try {
                    envelope = loadEnvelope(fileEntry);
                    if (envelope == null) {
                        continue;
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }
                SignalServiceContent content = null;
                if (!envelope.isReceipt()) {
                    try {
                        content = decryptMessage(envelope);
                    } catch (Exception e) {
                        continue;
                    }
                    handleMessage(envelope, content, ignoreAttachments);
                }
                handler.handleMessage(envelope, content, null);
                try {
                    Files.delete(fileEntry.toPath());
                } catch (IOException e) {
                    System.out.println("Failed to delete cached message file “" + fileEntry + "”: " + e.getMessage());
                }
            }
        }
    }

    public void receiveMessages(long timeout, TimeUnit unit, boolean returnOnTimeout, boolean ignoreAttachments, ReceiveMessageHandler handler) throws IOException {
        retryFailedReceivedMessages(handler, ignoreAttachments);
        final SignalServiceMessageReceiver messageReceiver = new SignalServiceMessageReceiver(serviceUrls, localIdentity.getToshiId(), localIdentity.getPassword(), Base64.encodeBytes(localIdentity.getSignalingKey()), USER_AGENT);
        SignalServiceMessagePipe messagePipe = null;

        try {
            messagePipe = messageReceiver.createMessagePipe();

            while (true) {
                //System.err.println("while");
                SignalServiceEnvelope envelope;
                SignalServiceContent content = null;
                Exception exception = null;
                final long now = new Date().getTime();
                try {
                    envelope = messagePipe.read(timeout, unit, new SignalServiceMessagePipe.MessagePipeCallback() {
                        @Override
                        public void onMessage(SignalServiceEnvelope envelope) {
                            // store message on disk, before acknowledging receipt to the server
                            try {
                                File cacheFile = getMessageCacheFile(envelope.getSource(), now, envelope.getTimestamp());
                                storeEnvelope(envelope, cacheFile);
                            } catch (IOException e) {
                                System.err.println("Failed to store encrypted message in disk cache, ignoring: " + e.getMessage());
                            }
                        }
                    });
                } catch (TimeoutException e) {
                    //System.err.println("Timeout: " + e.getMessage());
                    if (returnOnTimeout)
                        return;
                    continue;
                } catch (InvalidVersionException e) {
                    System.err.println("Ignoring error: " + e.getMessage());
                    continue;
                }
                if (!envelope.isReceipt()) {
                    try {
                        content = decryptMessage(envelope);
                    } catch (Exception e) {
                        exception = e;
                    }
                    handleMessage(envelope, content, ignoreAttachments);
                }
                handler.handleMessage(envelope, content, exception);
                if (exception == null || !(exception instanceof org.whispersystems.libsignal.UntrustedIdentityException)) {
                    File cacheFile = null;
                    try {
                        cacheFile = getMessageCacheFile(envelope.getSource(), now, envelope.getTimestamp());
                        Files.delete(cacheFile.toPath());
                    } catch (IOException e) {
                        System.out.println("Failed to delete cached message file “" + cacheFile + "”: " + e.getMessage());
                    }
                }
            }
        } finally {
            if (messagePipe != null)
                messagePipe.shutdown();
        }
    }

    private void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, boolean ignoreAttachments) {
        if (content != null) {
            if (content.getDataMessage().isPresent()) {
                SignalServiceDataMessage message = content.getDataMessage().get();
                handleSignalServiceDataMessage(message, false, envelope.getSource(), wallet.getOwnerAddress(), ignoreAttachments);
            }
            if (content.getSyncMessage().isPresent()) {
                SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();
                if (syncMessage.getSent().isPresent()) {
                    SignalServiceDataMessage message = syncMessage.getSent().get().getMessage();
                    handleSignalServiceDataMessage(message, true, envelope.getSource(), syncMessage.getSent().get().getDestination().get(), ignoreAttachments);
                }
                if (syncMessage.getRequest().isPresent()) {
                    RequestMessage rm = syncMessage.getRequest().get();
                    if (rm.isContactsRequest()) {
                        try {
                            sendContacts();
                        } catch (UntrustedIdentityException | IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (rm.isGroupsRequest()) {
                        try {
                            sendGroups();
                        } catch (UntrustedIdentityException | IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
                if (syncMessage.getGroups().isPresent()) {
                    File tmpFile = null;
                    try {
                        tmpFile = Util.createTempFile();
                        DeviceGroupsInputStream s = new DeviceGroupsInputStream(retrieveAttachmentAsStream(syncMessage.getGroups().get().asPointer(), tmpFile));
                        DeviceGroup g;
                        while ((g = s.read()) != null) {
                            GroupInfo syncGroup = groupStore.getGroup(g.getId());
                            if (syncGroup == null) {
                                syncGroup = new GroupInfo(g.getId());
                            }
                            if (g.getName().isPresent()) {
                                syncGroup.name = g.getName().get();
                            }
                            syncGroup.members.addAll(g.getMembers());
                            syncGroup.active = g.isActive();

                            if (g.getAvatar().isPresent()) {
                                retrieveGroupAvatarAttachment(g.getAvatar().get(), syncGroup.groupId);
                            }
                            groupStore.updateGroup(syncGroup);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (tmpFile != null) {
                            try {
                                Files.delete(tmpFile.toPath());
                            } catch (IOException e) {
                                System.out.println("Failed to delete temp file “" + tmpFile + "”: " + e.getMessage());
                            }
                        }
                    }
                    if (syncMessage.getBlockedList().isPresent()) {
                        // TODO store list of blocked numbers
                    }
                }
                if (syncMessage.getContacts().isPresent()) {
                    File tmpFile = null;
                    try {
                        tmpFile = Util.createTempFile();
                        DeviceContactsInputStream s = new DeviceContactsInputStream(retrieveAttachmentAsStream(syncMessage.getContacts().get().getContactsStream().asPointer(), tmpFile));
                        DeviceContact c;
                        while ((c = s.read()) != null) {
                            ContactInfo contact = contactStore.getContact(c.getNumber());
                            if (contact == null) {
                                contact = new ContactInfo();
                                contact.number = c.getNumber();
                            }
                            if (c.getName().isPresent()) {
                                contact.name = c.getName().get();
                            }
                            if (c.getColor().isPresent()) {
                                contact.color = c.getColor().get();
                            }
                            contactStore.updateContact(contact);

                            if (c.getAvatar().isPresent()) {
                                retrieveContactAvatarAttachment(c.getAvatar().get(), contact.number);
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (tmpFile != null) {
                            try {
                                Files.delete(tmpFile.toPath());
                            } catch (IOException e) {
                                System.out.println("Failed to delete temp file “" + tmpFile + "”: " + e.getMessage());
                            }
                        }
                    }
                }
            }
        }
    }

    private SignalServiceEnvelope loadEnvelope(File file) throws IOException {
        try (FileInputStream f = new FileInputStream(file)) {
            DataInputStream in = new DataInputStream(f);
            int version = in.readInt();
            if (version != 1) {
                return null;
            }
            int type = in.readInt();
            String source = in.readUTF();
            int sourceDevice = in.readInt();
            String relay = in.readUTF();
            long timestamp = in.readLong();
            byte[] content = null;
            int contentLen = in.readInt();
            if (contentLen > 0) {
                content = new byte[contentLen];
                in.readFully(content);
            }
            byte[] legacyMessage = null;
            int legacyMessageLen = in.readInt();
            if (legacyMessageLen > 0) {
                legacyMessage = new byte[legacyMessageLen];
                in.readFully(legacyMessage);
            }
            return new SignalServiceEnvelope(type, source, sourceDevice, relay, timestamp, legacyMessage, content);
        }
    }

    private void storeEnvelope(SignalServiceEnvelope envelope, File file) throws IOException {
        try (FileOutputStream f = new FileOutputStream(file)) {
            try (DataOutputStream out = new DataOutputStream(f)) {
                out.writeInt(1); // version
                out.writeInt(envelope.getType());
                out.writeUTF(envelope.getSource());
                out.writeInt(envelope.getSourceDevice());
                out.writeUTF(envelope.getRelay());
                out.writeLong(envelope.getTimestamp());
                if (envelope.hasContent()) {
                    out.writeInt(envelope.getContent().length);
                    out.write(envelope.getContent());
                } else {
                    out.writeInt(0);
                }
                if (envelope.hasLegacyMessage()) {
                    out.writeInt(envelope.getLegacyMessage().length);
                    out.write(envelope.getLegacyMessage());
                } else {
                    out.writeInt(0);
                }
            }
        }
    }

    public File getContactAvatarFile(String number) {
        return new File(avatarsPath, "contact-" + number);
    }

    private File retrieveContactAvatarAttachment(SignalServiceAttachment attachment, String number) throws IOException, InvalidMessageException {
        createPrivateDirectories(avatarsPath);
        if (attachment.isPointer()) {
            SignalServiceAttachmentPointer pointer = attachment.asPointer();
            return retrieveAttachment(pointer, getContactAvatarFile(number), false);
        } else {
            SignalServiceAttachmentStream stream = attachment.asStream();
            return retrieveAttachment(stream, getContactAvatarFile(number));
        }
    }

    public File getGroupAvatarFile(byte[] groupId) {
        return new File(avatarsPath, "group-" + Base64.encodeBytes(groupId).replace("/", "_"));
    }

    private File retrieveGroupAvatarAttachment(SignalServiceAttachment attachment, byte[] groupId) throws IOException, InvalidMessageException {
        createPrivateDirectories(avatarsPath);
        if (attachment.isPointer()) {
            SignalServiceAttachmentPointer pointer = attachment.asPointer();
            return retrieveAttachment(pointer, getGroupAvatarFile(groupId), false);
        } else {
            SignalServiceAttachmentStream stream = attachment.asStream();
            return retrieveAttachment(stream, getGroupAvatarFile(groupId));
        }
    }

    public File getAttachmentFile(long attachmentId) {
        return new File(attachmentsPath, attachmentId + "");
    }

    private File retrieveAttachment(SignalServiceAttachmentPointer pointer) throws IOException, InvalidMessageException {
        createPrivateDirectories(attachmentsPath);
        return retrieveAttachment(pointer, getAttachmentFile(pointer.getId()), true);
    }

    private File retrieveAttachment(SignalServiceAttachmentStream stream, File outputFile) throws IOException, InvalidMessageException {
        InputStream input = stream.getInputStream();

        try (OutputStream output = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[4096];
            int read;

            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
        return outputFile;
    }

    private File retrieveAttachment(SignalServiceAttachmentPointer pointer, File outputFile, boolean storePreview) throws IOException, InvalidMessageException {
        if (storePreview && pointer.getPreview().isPresent()) {
            File previewFile = new File(outputFile + ".preview");
            try (OutputStream output = new FileOutputStream(previewFile)) {
                byte[] preview = pointer.getPreview().get();
                output.write(preview, 0, preview.length);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                return null;
            }
        }

        final SignalServiceMessageReceiver messageReceiver = new SignalServiceMessageReceiver(serviceUrls, localIdentity.getToshiId(), localIdentity.getPassword(), Base64.encodeBytes(localIdentity.getSignalingKey()), USER_AGENT);

        File tmpFile = Util.createTempFile();
        try (InputStream input = messageReceiver.retrieveAttachment(pointer, tmpFile, MAX_ATTACHEMENT_SIZE_BYTES)) {
            try (OutputStream output = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[4096];
                int read;

                while ((read = input.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                return null;
            }
        } finally {
            try {
                Files.delete(tmpFile.toPath());
            } catch (IOException e) {
                System.out.println("Failed to delete temp file “" + tmpFile + "”: " + e.getMessage());
            }
        }
        return outputFile;
    }

    private InputStream retrieveAttachmentAsStream(SignalServiceAttachmentPointer pointer, File tmpFile) throws IOException, InvalidMessageException {
        final SignalServiceMessageReceiver messageReceiver = new SignalServiceMessageReceiver(serviceUrls, localIdentity.getToshiId(), localIdentity.getPassword(), Base64.encodeBytes(localIdentity.getSignalingKey()), USER_AGENT);
        return messageReceiver.retrieveAttachment(pointer, tmpFile, MAX_ATTACHEMENT_SIZE_BYTES);
    }

    private SignalServiceAddress getPushAddress(String number) throws InvalidNumberException {
        return new SignalServiceAddress(number);
    }


    public boolean isRemote() {
        return false;
    }

    private void sendGroups() throws IOException, UntrustedIdentityException {
        File groupsFile = Util.createTempFile();

        try {
            try (OutputStream fos = new FileOutputStream(groupsFile)) {
                DeviceGroupsOutputStream out = new DeviceGroupsOutputStream(fos);
                for (GroupInfo record : groupStore.getGroups()) {
                    out.write(new DeviceGroup(record.groupId, Optional.fromNullable(record.name),
                            new ArrayList<>(record.members), createGroupAvatarAttachment(record.groupId),
                            record.active));
                }
            }

            if (groupsFile.exists() && groupsFile.length() > 0) {
                try (FileInputStream groupsFileStream = new FileInputStream(groupsFile)) {
                    SignalServiceAttachmentStream attachmentStream = SignalServiceAttachment.newStreamBuilder()
                            .withStream(groupsFileStream)
                            .withContentType("application/octet-stream")
                            .withLength(groupsFile.length())
                            .build();

                    sendSyncMessage(SignalServiceSyncMessage.forGroups(attachmentStream));
                }
            }
        } finally {
            try {
                Files.delete(groupsFile.toPath());
            } catch (IOException e) {
                System.out.println("Failed to delete temp file “" + groupsFile + "”: " + e.getMessage());
            }
        }
    }

    private void sendContacts() throws IOException, UntrustedIdentityException {
        File contactsFile = Util.createTempFile();

        try {
            try (OutputStream fos = new FileOutputStream(contactsFile)) {
                DeviceContactsOutputStream out = new DeviceContactsOutputStream(fos);
                for (ContactInfo record : contactStore.getContacts()) {
                    out.write(new DeviceContact(record.number, Optional.fromNullable(record.name),
                                                createContactAvatarAttachment(record.number), Optional.fromNullable(record.color),
                                                Optional.absent()));
                }
            }

            if (contactsFile.exists() && contactsFile.length() > 0) {
                try (FileInputStream contactsFileStream = new FileInputStream(contactsFile)) {
                    SignalServiceAttachmentStream attachmentStream = SignalServiceAttachment.newStreamBuilder()
                            .withStream(contactsFileStream)
                            .withContentType("application/octet-stream")
                            .withLength(contactsFile.length())
                            .build();

                    // TODO: no idea if "false" is right here
                    sendSyncMessage(SignalServiceSyncMessage.forContacts(new ContactsMessage(attachmentStream, false)));
                }
            }
        } finally {
            try {
                Files.delete(contactsFile.toPath());
            } catch (IOException e) {
                System.out.println("Failed to delete temp file “" + contactsFile + "”: " + e.getMessage());
            }
        }
    }

    public ContactInfo getContact(String number) {
        return contactStore.getContact(number);
    }

    public GroupInfo getGroup(byte[] groupId) {
        return groupStore.getGroup(groupId);
    }

}
