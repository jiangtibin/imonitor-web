package com.hengtiansoft.imonitor.web.management.user;

import com.hengtiansoft.imonitor.web.security.entity.user.User;

public interface UserService {

    User registryUser(UserDTO userDTO);
}
