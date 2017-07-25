// provides a class similar to org.whispersystems.signalservice.internal.push.AccountAttributes
// with only the required attributes. useful for use on legacy signal servers that don't
// support voice or video

package com.bakkenbaeck.token.headless.signal;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DefaultAccountAttributes {

  @JsonProperty
  private String  signalingKey;

  @JsonProperty
  private int     registrationId;

  @JsonProperty
  private boolean fetchesMessages;

  public DefaultAccountAttributes(String signalingKey, int registrationId, boolean fetchesMessages) {
    this.signalingKey   = signalingKey;
    this.registrationId = registrationId;
    this.fetchesMessages = fetchesMessages;
  }

  public DefaultAccountAttributes() {}

  public String getSignalingKey() {
    return signalingKey;
  }

  public int getRegistrationId() {
    return registrationId;
  }

  public boolean isFetchesMessages() {
    return fetchesMessages;
  }
}
