package com.reachrich.reachrichgateway.filter;

import static com.reachrich.reachrichgateway.util.Const.ACCESS_TOKEN_HEADER;
import static com.reachrich.reachrichgateway.util.Const.ISSUER;
import static java.util.Objects.isNull;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.reachrich.reachrichgateway.jwt.JwtAuthenticationToken;
import java.util.Date;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final JWTVerifier jwtVerifier;

    public JwtAuthenticationFilter(@Qualifier("jwtVerifier") JWTVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();
        List<HttpCookie> cookie = cookies.get(ACCESS_TOKEN_HEADER);

        try {
            if (!isNull(cookie) && cookie.size() == 1) {
                String accessToken = cookie.get(0).getValue();
                DecodedJWT decodedJWT = jwtVerifier.verify(accessToken);

                if (isValidAccessToken(decodedJWT)) {
                    String audience = decodedJWT.getAudience().get(0);

                    // TODO: credentials, authorities 다룰지?
                    Authentication jwtAuthenticationToken =
                        new JwtAuthenticationToken(audience, null, null);

                    return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                            jwtAuthenticationToken));
                }
            }
        } catch (JWTVerificationException e) {
            log.warn("잘못된 access token 포함한 요청입니다. : {}", e.getMessage());
        }

        return chain.filter(exchange);
    }

    // TODO: issuer 상수로
    private boolean isValidAccessToken(DecodedJWT decodedJWT) {
        return decodedJWT.getExpiresAt().after(new Date())
            && ISSUER.equals(decodedJWT.getIssuer());
    }
}
