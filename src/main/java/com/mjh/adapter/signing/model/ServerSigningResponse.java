package com.mjh.adapter.signing.model;

import com.mjh.adapter.signing.model.common.CommonResponse;

import java.util.List;

public class ServerSigningResponse extends CommonResponse {
    private String trxId;
    private String data;
    private List<byte[]> crlEntries;
    private List<byte[]> ocspEntries;
    private int requestId;
    private String archiveId;

    public String getArchiveId() {
        return archiveId;
    }

    public void setArchiveId(String archiveId) {
        this.archiveId = archiveId;
    }

    public int getRequestId() {
        return requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    public String getTrxId() {
        return trxId;
    }

    public void setTrxId(String trxId) {
        this.trxId = trxId;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public List<byte[]> getCrlEntries() {
        return crlEntries;
    }

    public void setCrlEntries(List<byte[]> crlEntries) {
        this.crlEntries = crlEntries;
    }

    public List<byte[]> getOcspEntries() {
        return ocspEntries;
    }

    public void setOcspEntries(List<byte[]> ocspEntries) {
        this.ocspEntries = ocspEntries;
    }
}
