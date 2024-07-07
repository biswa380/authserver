package com.eshop.authserver.configs;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

// https://www.youtube.com/watch?v=9oFyzXgbzwo
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired


    @Bean
    @Order(1)
    public SecurityFilterChain webFilterChainForOauth(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults());
        httpSecurity.exceptionHandling(e -> e.authenticationEntryPoint(
            new LoginUrlAuthenticationEntryPoint("/login")
        ));
        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defauFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
        .csrf(csrf -> csrf.disable())
        // .cors(cors -> cors.disable())
        .authorizeHttpRequests(request -> request.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
        return httpSecurity.build();
        // return httpSecurity
        // .csrf(csrf -> csrf.disable())
        // .authorizeHttpRequests(auth -> auth.requestMatchers("/register", "/error", "/css/**", "/login").permitAll()
        // .anyRequest().authenticated())
        // .httpBasic(Customizer.withDefaults())
        // .formLogin(Customizer.withDefaults())
        // .build();
    }

    // @Bean
    // public UserDetailsService userDetailsService() {
    //     UserDetails userDetails = User.withUsername("admin")
    //     .password("admin")
    //     .authorities("read")
    //     .build();

    //     return new InMemoryUserDetailsManager(userDetails);
    // } 

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
        // return NoOpPasswordEncoder.getInstance();
    }
    

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        RegisteredClient registeredClient =  RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("web-client")
        .clientSecret("webclient12345678")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .redirectUri("http://localhost:4200/login")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantTypes(
            grantType -> {
                grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
            }
        )
        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
        .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // return AuthorizationServerSettings.builder().build();
        return AuthorizationServerSettings.builder()
        .issuer("http://localhost:9000")
        .authorizationEndpoint("/oauth2/authorize")
        .tokenEndpoint("/oauth2/token")
        .tokenIntrospectionEndpoint("/oauth2/introspect")
        .tokenRevocationEndpoint("/oauth2/revoke")
        .jwkSetEndpoint("/oauth2/jwks")
        .oidcUserInfoEndpoint("/userinfo")
        .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keys = keyPairGenerator.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keys.getPublic();
        PrivateKey privateKey = keys.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
