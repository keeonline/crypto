package com.example.crypto.domain;

public class ReEncryptedPinData {
    private final String before;
    private final String beforeKey;
    private final String pinData;
    private final String after;
    private final String afterKey;

    public ReEncryptedPinData(String before, String beforeKey, String pinData, String after, String afterKey) {
        this.before = before;
        this.beforeKey = beforeKey;
        this.pinData = pinData;
        this.after = after;
        this.afterKey = afterKey;
    }

    public String getAfterKey() {
        return afterKey;
    }

    public String getAfter() {
        return after;
    }

    public String getPinData() {
        return pinData;
    }

    public String getBeforeKey() {
        return beforeKey;
    }

    public String getBefore() {
        return before;
    }

}
