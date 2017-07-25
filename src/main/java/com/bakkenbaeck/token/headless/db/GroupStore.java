package com.bakkenbaeck.token.headless.db;

import com.bakkenbaeck.token.headless.signal.GroupInfo;
import java.util.List;

public interface GroupStore {
    public void updateGroup(GroupInfo group);
    public GroupInfo getGroup(byte[] groupId);
    public List<GroupInfo> getGroups();
}
