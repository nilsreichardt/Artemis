package de.tum.in.www1.artemis.config;

import java.util.*;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import de.tum.in.www1.artemis.config.lti.CustomLti13Configurer;
import de.tum.in.www1.artemis.security.Role;
import de.tum.in.www1.artemis.security.jwt.JWTConfigurer;
import de.tum.in.www1.artemis.security.jwt.TokenProvider;
import de.tum.in.www1.artemis.service.user.PasswordService;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
// ToDo: currently this cannot be replaced as recommended by
// https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
// as that would break the SAML2 login functionality. For more information, see
// https://github.com/ls1intum/Artemis/pull/5721.
public class SecurityConfiguration {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final UserDetailsService userDetailsService;

    private final TokenProvider tokenProvider;

    private final CorsFilter corsFilter;

    private final SecurityProblemSupport problemSupport;

    private final PasswordService passwordService;

    private final Optional<AuthenticationProvider> remoteUserAuthenticationProvider;

    @Value("#{'${spring.prometheus.monitoringIp:127.0.0.1}'.split(',')}")
    private List<String> monitoringIpAddresses;

    private final Environment env;

    public SecurityConfiguration(AuthenticationManagerBuilder authenticationManagerBuilder, UserDetailsService userDetailsService, TokenProvider tokenProvider,
            CorsFilter corsFilter, SecurityProblemSupport problemSupport, PasswordService passwordService, Optional<AuthenticationProvider> remoteUserAuthenticationProvider,
            Environment env) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.userDetailsService = userDetailsService;
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.problemSupport = problemSupport;
        this.passwordService = passwordService;
        this.remoteUserAuthenticationProvider = remoteUserAuthenticationProvider;
        this.env = env;
    }

    /**
     * initialize the security configuration by specifying that the (internal) user details service and (if available) an external authentication provider (e.g. JIRA)
     * should be used
     */
    @PostConstruct
    public void init() {
        try {
            // here we configure 2 authentication provider: 1) the user details service for internal authentication using the Artemis database...
            authenticationManagerBuilder.userDetailsService(userDetailsService);
            // ... and 2), if specified a remote (or external) user authentication provider (e.g. JIRA)
            remoteUserAuthenticationProvider.ifPresent(authenticationManagerBuilder::authenticationProvider);
            // When users try to authenticate, Spring will always first ask the remote user authentication provider (e.g. JIRA) if available, and only if this one fails,
            // it will ask the user details service (internal DB) for authentication.
        }
        catch (Exception e) {
            throw new BeanInitializationException("Security configuration failed", e);
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return this.passwordService.getPasswordEncoder();
    }

    @Bean
    RoleHierarchy roleHierarchy() {
        var roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("""
                    ROLE_ADMIN > ROLE_INSTRUCTOR
                    ROLE_INSTRUCTOR > ROLE_EDITOR
                    ROLE_EDITOR > ROLE_TA
                    ROLE_TA > ROLE_USER
                """);
        return roleHierarchy;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // @formatter:off
        return webSecurity -> webSecurity.ignoring()
            .requestMatchers(new AntPathRequestMatcher("/**", HttpMethod.OPTIONS.toString()))
            .requestMatchers(new AntPathRequestMatcher("/app/**/*.{js,html}"))
            .requestMatchers(new AntPathRequestMatcher("/i18n/**"))
            .requestMatchers(new AntPathRequestMatcher("/content/**"))
            .requestMatchers(new AntPathRequestMatcher("/api-docs/**"))
            .requestMatchers(new AntPathRequestMatcher("/api.html"))
            .requestMatchers(new AntPathRequestMatcher("/test/**"));
        // @formatter:on
    }

    /**
     * Only allow the configured IP addresses to access the prometheus endpoint
     *
     * @return an access check like "hasIpAddress('127.0.0.1') or hasIpAddress('::1')" that can be used as argument for
     *         {@link org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.AuthorizedUrl#access(String)}}
     */
    private String getMonitoringAccessDefinition() {
        return monitoringIpAddresses.stream().map(ip -> String.format("hasIpAddress(\"%s\")", ip)).collect(Collectors.joining(" or "));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .csrf(AbstractHttpConfigurer::disable)
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class).exceptionHandling(handler -> handler.authenticationEntryPoint(problemSupport).accessDeniedHandler(problemSupport))
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable) // this is already configured using nginx
                // TODO: investigate exactly whether the following works in our setup or not
                // .contentSecurityPolicy("default-src 'self'; connect-src: 'self' 'https://sentry.io' 'ws:' 'wss:'; frame-src * data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src * data:; font-src 'self' data:")
                .contentSecurityPolicy((policy) -> policy.policyDirectives("script-src 'self' 'unsafe-inline' 'unsafe-eval'"))
                .referrerPolicy(policy ->policy.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .permissionsPolicy(policy -> policy.policy("camera=(), fullscreen=(*), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()"))
            )
            .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(requests -> requests
                .requestMatchers(new AntPathRequestMatcher("/api/admin/**")).hasAuthority(Role.ADMIN.getAuthority())
                .requestMatchers(new AntPathRequestMatcher("/api/public/**")).permitAll()
                // TODO: Remove the following three lines in June 2024 together with LegacyResource
                .requestMatchers(new AntPathRequestMatcher(HttpMethod.POST.name(), "/api/programming-exercises/new-result")).permitAll()
                .requestMatchers(new AntPathRequestMatcher(HttpMethod.POST.name(), "/api/programming-submissions/*")).permitAll()
                .requestMatchers(new AntPathRequestMatcher(HttpMethod.POST.name(), "/api/programming-exercises/test-cases-changed/*")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/websocket/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/.well-known/jwks.json")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/management/prometheus/**")).access(getMonitoringAccessDefinition())
                .requestMatchers(new AntPathRequestMatcher("/api/**")).authenticated()
            )
            .apply(securityConfigurerAdapter());

        Collection<String> activeProfiles = Arrays.asList(env.getActiveProfiles());
        if (activeProfiles.contains("lti")) {
            http.apply(new CustomLti13Configurer());
        }
        // @formatter:on

        return http.build();
    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }
}
