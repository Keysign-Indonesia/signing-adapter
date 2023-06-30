package com.mjh.adapter.signing.model;

import com.mjh.adapter.signing.common.ConstantID;
import io.swagger.v3.oas.annotations.media.Schema;

public class DocFileSigningRequest {
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signing Profile name")
    private String profileName;
    @Schema(description = "Signing doc password if any | not implemented yet")
    private String docpass;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Document source path")
    private String src;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Document destination path")
    private String dest;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Specimen path")
    private String spesimenPath;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature reason")
    private String reason;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature location")
    private String location;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature page")
    private int visSignaturePage = 1;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature rectangle left lower x coordinate")
    private int visLLX = 0;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature rectangle left lower y coordinate")
    private int visLLY = 0;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature rectangle upper right x coordinate")
    private int visURX = 0;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature rectangle upper right y coordinate")
    private int visURY = 0;
//    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED")
    private String certificatelevel;
    @Schema(description = "Json Web Token for security purpose")
    private String jwToken;
    @Schema(description = "Reference Token for relation purpose")
    private String refToken;
    @Schema(description = "Signing retry flag, fill 1 for retry")
    private String retryFlag;

    public String getRetryFlag() {
        return retryFlag;
    }

    public void setRetryFlag(String retryFlag) {
        this.retryFlag = retryFlag;
    }

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
