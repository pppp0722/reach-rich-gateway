package com.reachrich.reachrichgateway.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${spring.jwt.issuer}")
    private String issuer;

    @Value("${spring.jwt.client-secret}")
    private String clientSecret;

    @Bean
    @Qualifier("jwtVerifier")
    public JWTVerifier jwtVerifier() {
        return JWT.require(Algorithm.HMAC512(clientSecret))
            .withIssuer(issuer)
            .build();
    }
}
