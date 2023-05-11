package com.hengtiansoft.imonitor.web.security.jwt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "app.security.jwt")
public class JwtProperties {

        @NotBlank(message = "token安全密钥不能为空, 请在系统环境或命令行参数配置安全密钥")
        private String secretKey;

        @Pattern(message = "需要匹配正则表达式\"^([1-9][0-9]*(\\*[1-9][0-9]*)*)$\"\n\t" +
                "e.g：6000 | 60*1000 | 5*60*1000",
                regexp = "^([1-9][0-9]*(\\*[1-9][0-9]*)*)$")
        private String accessTokenExpiration;

        @Pattern(message = "需要匹配正则表达式\"^([1-9][0-9]*(\\*[1-9][0-9]*)*)$\"\n\t" +
                "e.g：6000 | 60*1000 | 5*60*1000",
                regexp = "^([1-9][0-9]*(\\*[1-9][0-9]*)*)$")
        private String refreshTokenExpiration;

        @NotNull(message = "enabled can only applied for true or false")
        private Boolean enabled;

}
