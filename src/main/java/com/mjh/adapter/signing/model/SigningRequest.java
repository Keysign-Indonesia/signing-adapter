package com.mjh.adapter.signing.model;

public class SigningRequest {
    private String workerName;
    private String data;
    private String systemId;
    private String shaChecksum;
    private String retryFlag;
    private String refToken;

    public String getWorkerName() {
        return workerName;
    }

    public void setWorkerName(String workerName) {
        this.workerName = workerName;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSystemId() {
        return systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId;
    }

    public String getShaChecksum() {
        return shaChecksum;
    }

    public void setShaChecksum(String shaChecksum) {
        this.shaChecksum = shaChecksum;
    }

    public String getRetryFlag() {
        return retryFlag;
    }

    public void setRetryFlag(String retryFlag) {
        this.retryFlag = retryFlag;
    }

    public String getRefToken() {
        return refToken;
    }

    public void setRefToken(String refToken) {
        this.refToken = refToken;
    }
}
