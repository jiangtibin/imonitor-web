package com.hengtiansoft.imonitor.web.security.cas;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "app.security.cas", ignoreUnknownFields = false)
public class CasProperties {

    @NotNull
    private String serverUrlPrefix;

    @NotNull
    private String serverLoginUrl;

    @NotNull
    private String clientHostUrl;

    @NotBlank(message = "A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated")
    private String key;

    @NotNull(message = "enabled can only applied for true or false")
    private Boolean enabled;

    private CasValidationType validationType = CasValidationType.CAS3;
}

