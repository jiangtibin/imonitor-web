package com.hengtiansoft.imonitor.web.security.entity.permission;

public enum Permissions {
    DINGDING_CHAT_LIST("DINGDING::CHAT::LIST"),
    DINGDING_FILE_LIST("DINGDING::FILE::LIST"),
    WECHAT_CHAT_LIST("WECHAT::CHAT::LIST"),
    WECHAT_FILE_LIST("WECHAT::FILE::LIST"),
    USER_READ("USER::READ"),
    USER_ADD("USER::ADD"),
    USER_UPDATE("USER::UPDATE"),
    USER_DELETE("USER::DELETE");

    private final String permission;
    Permissions(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
