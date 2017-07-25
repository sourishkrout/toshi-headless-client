package com.bakkenbaeck.token.headless.db;

public interface LocalIdentityStore {

    /**
       Loads the local identity, returning null if none for the given toshiId exists
     **/
    public LocalIdentity loadLocalIdentity(String toshiId);

    /**
       returns boolean whether the given user exists or not
    **/
    public boolean exists(String toshiId);

    /**
       Saves the given local identity
     **/
    public void saveLocalIdentity(LocalIdentity identity);

}
