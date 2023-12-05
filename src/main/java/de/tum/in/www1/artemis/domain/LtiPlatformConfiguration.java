package de.tum.in.www1.artemis.domain;

import javax.annotation.Nullable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Represents the configuration for an LTI platform.
 * Stores details such as registration ID, client ID, and various URIs needed for LTI communication.
 */
@Entity
@Table(name = "lti_platform_configuration")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class LtiPlatformConfiguration extends DomainObject {

    public static final String ENTITY_NAME = "ltiPlatformConfiguration";

    @NotNull
    @Column(name = "registration_id", nullable = false)
    private String registrationId;

    @NotNull
    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Nullable
    @Column(name = "original_url")
    private String originalUrl;

    @Nullable
    @Column(name = "custom_name")
    private String customName;

    @NotNull
    @Column(name = "authorization_uri", nullable = false)
    private String authorizationUri;

    @NotNull
    @Column(name = "jwk_set_uri", nullable = false)
    private String jwkSetUri;

    @NotNull
    @Column(name = "token_uri", nullable = false)
    private String tokenUri;

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    @Nullable
    public String getOriginalUrl() {
        return originalUrl;
    }

    public void setOriginalUrl(@Nullable String issuer) {
        this.originalUrl = issuer;
    }

    @Nullable
    public String getCustomName() {
        return customName;
    }

    public void setCustomName(@Nullable String customName) {
        this.customName = customName;
    }

}
