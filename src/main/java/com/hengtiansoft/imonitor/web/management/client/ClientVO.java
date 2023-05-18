package com.hengtiansoft.imonitor.web.management.client;

import com.hengtiansoft.imonitor.web.security.entity.client.Client;
import com.hengtiansoft.imonitor.web.security.entity.token.Token;

public record ClientVO(
        Client client,

        Token token
) {
}
