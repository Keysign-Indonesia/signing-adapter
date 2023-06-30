package com.mjh.adapter.signing.model;

import com.mjh.adapter.signing.model.common.CommonResponse;

import java.util.List;

public class GetSignerCertChainResponse extends CommonResponse {
    private String profileName;

    private List<byte[]> certs;

    public List<byte[]> getCerts() {
        return this.certs;
    }

    public void setCerts(List<byte[]> certs) {
        this.certs = certs;
    }

    public String getProfileName() {
        return this.profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }
}
