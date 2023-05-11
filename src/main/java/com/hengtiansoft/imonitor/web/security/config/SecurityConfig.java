package com.hengtiansoft.imonitor.web.security.config;

import com.hengtiansoft.imonitor.web.security.CasAndJwtAuthEntryPoint;
import com.hengtiansoft.imonitor.web.security.cas.CasAuthenticationRedirectStrategy;
import com.hengtiansoft.imonitor.web.security.cas.CasProperties;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenRepository;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenService;
import com.hengtiansoft.imonitor.web.security.entity.user.AuthUser;
import com.hengtiansoft.imonitor.web.security.entity.user.UserRepository;
import com.hengtiansoft.imonitor.web.security.jwt.*;
import lombok.RequiredArgsConstructor;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.apereo.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtLogoutHandler jwtLogoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/backend/v1/auth/**").permitAll()
                .requestMatchers("/backend/v1/test/testAdmin").hasRole(Role.ADMIN.name())
                .requestMatchers("/backend/v1/test/testWebUser").hasRole(Role.WEB_USER.name())
                .requestMatchers("/backend/v1/test/testApiUser").hasRole(Role.API_USER.name())
                .anyRequest().authenticated()
                .and()
                .authenticationManager(authenticationManager())
                .exceptionHandling().authenticationEntryPoint(casAndJwtAuthenticationEntryPoint())
                .and()
                .logout()
                .logoutUrl("/backend/v1/auth/logout")
                .addLogoutHandler(jwtLogoutHandler)
                .addLogoutHandler(new SecurityContextLogoutHandler())
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());

        if (jwtProperties().getEnabled()) {
            httpSecurity.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        if (casProperties().getEnabled()) {
            httpSecurity.addFilterBefore(casAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        }

        return httpSecurity.build();
    }

    @Bean
    public CasProperties casProperties() {
        return new CasProperties();
    }

    @Bean
    public JwtProperties jwtProperties() {
        return new JwtProperties();
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casProperties().getClientHostUrl());
        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    @Bean
    public CasAndJwtAuthEntryPoint casAndJwtAuthenticationEntryPoint() {
        CasAndJwtAuthEntryPoint  casAndJwtAuthEntryPoint = new CasAndJwtAuthEntryPoint();
        casAndJwtAuthEntryPoint.setLoginUrl(casProperties().getServerLoginUrl());
        casAndJwtAuthEntryPoint.setServiceProperties(serviceProperties());
        casAndJwtAuthEntryPoint.setEncodeServiceUrlWithSessionId(true);
        casAndJwtAuthEntryPoint.setCasEnabled(casProperties().getEnabled());
        casAndJwtAuthEntryPoint.setJwtEnabled(jwtProperties().getEnabled());
        casAndJwtAuthEntryPoint.setAuthenticationRedirectStrategy(new CasAuthenticationRedirectStrategy());
        return casAndJwtAuthEntryPoint;
    }

    /**
     * CAS认证过滤器
     */
    @Bean
    @ConditionalOnProperty(name = "app.security.cas.enabled", havingValue = "true", matchIfMissing = true)
    public CasAuthenticationFilter casAuthenticationFilter() {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        casAuthenticationFilter.setFilterProcessesUrl(casProperties().getServerLoginUrl());
        return casAuthenticationFilter;
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.cas.enabled", havingValue = "true", matchIfMissing = true)
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(casAuthUserDetailsService());
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(casServiceTicketValidator());
        casAuthenticationProvider.setKey(casProperties().getKey());
        return casAuthenticationProvider;
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.cas.enabled", havingValue = "true", matchIfMissing = true)
    public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> casAuthUserDetailsService() {
        return token -> userRepository
                .findByEmail(token.getPrincipal().toString())
                .map(AuthUser::new)
                .orElseThrow(() -> new AccessDeniedException("该用户没有权限登录IMonitor, 请联系管理员!"));
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.cas.enabled", havingValue = "true", matchIfMissing = true)
    public Cas20ServiceTicketValidator casServiceTicketValidator() {
        return switch (casProperties().getValidationType()) {
            case CAS -> new Cas20ServiceTicketValidator(casProperties().getServerUrlPrefix());
            case CAS3 -> new Cas30ServiceTicketValidator(casProperties().getServerUrlPrefix());
        };
    }

    @Bean
    public JwtProvider jwtProvider() {
        return new JwtProvider(jwtProperties());
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.jwt.enabled", havingValue = "true", matchIfMissing = true)
    JwtTokenService jwtTokenService() {return new TokenService(tokenRepository);}

    @Bean
    @ConditionalOnProperty(name = "app.security.jwt.enabled", havingValue = "true", matchIfMissing = true)
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter();
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager());
        jwtAuthenticationFilter.setJwtProvider(jwtProvider());
        jwtAuthenticationFilter.setAuthenticationFailureHandler(
                new AuthenticationEntryPointFailureHandler(casAndJwtAuthenticationEntryPoint()));
        return jwtAuthenticationFilter;
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.jwt.enabled", havingValue = "true", matchIfMissing = true)
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        jwtAuthenticationProvider.setJwtProvider(jwtProvider());
        jwtAuthenticationProvider.setJwtService(jwtTokenService());
        jwtAuthenticationProvider.setKey(jwtProperties().getSecretKey());
        jwtAuthenticationProvider.setAuthenticationUserDetailsService(jwtAuthUserDetailsService());
        return jwtAuthenticationProvider;
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.jwt.enabled", havingValue = "true", matchIfMissing = true)
    public AuthenticationUserDetailsService<JwtTokenAuthenticationToken> jwtAuthUserDetailsService() {
        return token -> userRepository
                .findByEmail(token.getPrincipal().toString())
                .map(AuthUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("用户名或密码错误"));
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository
                .findByEmail(username)
                .map(AuthUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("用户名或密码错误"));
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = new ArrayList<>(3);
        providers.add(daoAuthenticationProvider());
        if (jwtProperties().getEnabled()) {
            providers.add(jwtAuthenticationProvider());
        }

        if (casProperties().getEnabled()) {
            providers.add(casAuthenticationProvider());
        }
        return new ProviderManager(providers);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
