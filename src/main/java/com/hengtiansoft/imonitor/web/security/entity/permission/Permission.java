package com.hengtiansoft.imonitor.web.security.entity.permission;

import static com.hengtiansoft.imonitor.web.security.entity.permission.PermissionType.API;
import static com.hengtiansoft.imonitor.web.security.entity.permission.PermissionType.MENU;

public enum Permission {
    DINGDING_CHAT_LIST("DINGDING::CHAT::LIST", "/dingding/chat/list", MENU),

    DINGDING_FILE_LIST("DINGDING::FILE::LIST", "/dingding/file/list", MENU),

    WECHAT_CHAT_LIST("WECHAT::CHAT::LIST", "/wechat/chat/list", MENU),

    WECHAT_FILE_LIST("WECHAT::FILE::LIST", "/wechat/file/list", MENU),

    USER_READ("USER::READ", "/uer/list", MENU),

    USER_ADD("USER::ADD", "/user/registryUser", MENU),

    USER_UPDATE("USER::UPDATE", "/user/update", MENU),

    USER_DELETE("USER::DELETE", "/user/delete", MENU),

    CLIENT_ADD("CLIENT::ADD", "/client/registryClient", MENU),

    API_TEST("API::TEST", "", API);

    private final String permission;

    private final String path;

    private final PermissionType permissionType;

    Permission(String permission, String path, PermissionType permissionType) {
        this.permission = permission;
        this.path = path;
        this.permissionType = permissionType;
    }

    public String getPermission() {
        return this.permission;
    }

    public String getPath() {return this.path;}

    public PermissionType getPermissionType() {return this.permissionType;}

    public String getExpression() {
        return "hasAuthority('" + this.getPermission() + "')";
    }
}
