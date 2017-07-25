package com.bakkenbaeck.token.headless.db;

import com.bakkenbaeck.token.headless.signal.ThreadInfo;
import java.util.List;

public interface ThreadStore {
    public void updateThread(ThreadInfo thread);
    public ThreadInfo getThread(String id);
    public List<ThreadInfo> getThreads();
}
