package com.mjh.adapter.signing.model;

import com.mjh.adapter.signing.common.ConstantID;
import io.swagger.annotations.ApiModelProperty;

public class DocFileSigningRequest {
    @ApiModelProperty(notes = "Signing Profile name", required = true)
    private String profileName;
    @ApiModelProperty(notes = "Signing doc password if any | not implemented yet")
    private String docpass;
    @ApiModelProperty(notes = "Document source path", required = true)
    private String src;
    @ApiModelProperty(notes = "Document destination path", required = true)
    private String dest;
    @ApiModelProperty(notes = "Specimen path", required = true)
    private String spesimenPath;
    @ApiModelProperty(notes = "Digital signature reason", required = true)
    private String reason;
    @ApiModelProperty(notes = "Digital signature location", required = true)
    private String location;
    @ApiModelProperty(notes = "Digital signature page", required = true)
    private int visSignaturePage = 1;
    @ApiModelProperty(notes = "Digital signature rectangle left lower x coordinate", required = true)
    private int visLLX = 0;
    @ApiModelProperty(notes = "Digital signature rectangle left lower y coordinate", required = true)
    private int visLLY = 0;
    @ApiModelProperty(notes = "Digital signature rectangle upper right x coordinate", required = true)
    private int visURX = 0;
    @ApiModelProperty(notes = "Digital signature rectangle upper right y coordinate", required = true)
    private int visURY = 0;
    @ApiModelProperty(notes = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED", required = true)
    private String certificatelevel;
    @ApiModelProperty(notes = "Json Web Token for security purpose")
    private String jwToken;
    @ApiModelProperty(notes = "Reference Token for relation purpose")
    private String refToken;

    public String getRetryFlag() {
        return retryFlag;
    }

    public void setRetryFlag(String retryFlag) {
        this.retryFlag = retryFlag;
    }

    @ApiModelProperty(notes = "Signing retry flag, fill 1 for retry")
    private String retryFlag;

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getDocpass() {
        return docpass;
    }

    public void setDocpass(String docpass) {
        this.docpass = docpass;
    }

    public String getSrc() {
        return src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public String getDest() {
        return dest;
    }

    public void setDest(String dest) {
        this.dest = dest;
    }

    public String getSpesimenPath() {
        return spesimenPath;
    }

    public void setSpesimenPath(String spesimenPath) {
        this.spesimenPath = spesimenPath;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public int getVisSignaturePage() {
        return visSignaturePage;
    }

    public void setVisSignaturePage(int visSignaturePage) {
        this.visSignaturePage = visSignaturePage;
    }

    public int getVisLLX() {
        return visLLX;
    }

    public void setVisLLX(int visLLX) {
        this.visLLX = visLLX;
    }

    public int getVisLLY() {
        return visLLY;
    }

    public void setVisLLY(int visLLY) {
        this.visLLY = visLLY;
    }

    public int getVisURX() {
        return visURX;
    }

    public void setVisURX(int visURX) {
        this.visURX = visURX;
    }

    public int getVisURY() {
        return visURY;
    }

    public void setVisURY(int visURY) {
        this.visURY = visURY;
    }

    public String getCertificatelevel() {
        return certificatelevel;
    }

    public void setCertificatelevel(String certificatelevel) {
        this.certificatelevel = certificatelevel;
    }

    public String checkInput() {
        String check = "";
        if(profileName == null || "".equals(profileName.trim())) {

        }else if(src == null || "".equals(src.trim())) {
        }else if(dest == null || "".equals(dest.trim())) {
        }else if(reason == null || "".equals(reason.trim())) {
        }else if(location == null || "".equals(location.trim())) {
        }else if(spesimenPath == null || "".equals(spesimenPath.trim())) {
        }else if(certificatelevel == null || "".equals(certificatelevel.trim())) {

        }else {
            check = ConstantID.checkInputOK;
        }
        return check;
    }

    public String getJwToken() {
        return jwToken;
    }

    public void setJwToken(String jwToken) {
        this.jwToken = jwToken;
    }

    public String getRefToken() {
        return refToken;
    }

    public void setRefToken(String refToken) {
        this.refToken = refToken;
    }
}
