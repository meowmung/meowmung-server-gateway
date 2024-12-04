package com.example.gateway.config;

import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private JwtUtils jwtUtils;
    public AuthorizationHeaderFilter(JwtUtils tokenProvider){
        super(Config.class);
        this.jwtUtils = tokenProvider;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("AuthorizationHeaderFilter invoked");

            String authorizationHeader = exchange.getRequest().getHeaders().getFirst(config.headerName);
            log.info("Authorization Header: {}", authorizationHeader);

            if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(config.granted+" ")) {
                String token = authorizationHeader.substring(7); // Bearer
                log.info("Extracted Token: {}", token);

                try {
                    if (jwtUtils.isValidToken(token)) {
                        log.info("Token is valid");

                        Map<String, Object> userInfo = jwtUtils.parseToken(token);
//                        addAuthorizationHeaders(exchange. getRequest(), userInfo);
                        ServerWebExchange mutatedExchange = addAuthorizationHeaders(exchange, userInfo);

                        log.info("User Info added to headers: {}", userInfo);

                        return chain.filter(mutatedExchange);
                    }
                    log.warn("Token is invalid");

                } catch (Exception e) {
                    log.error("Token validation error: {}", e.getMessage());
                }
                log.warn("Authorization header is missing or does not start with '{}'", config.granted);

            }
            return unauthorizedResponse(exchange); // Token is not valid, respond with unauthorized
        };
    }

    // 인증 실패 Response
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private ServerWebExchange addAuthorizationHeaders(ServerWebExchange exchange, Map<String, Object> userInfo) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-Authorization-email", userInfo.get("email").toString())
                .header("X-Authorization-nickname", userInfo.get("nickname").toString())
                .header("X-Authorization-memberId", userInfo.get("memberId").toString())
                .build();
        log.info("Mutated Request Headers: {}", mutatedRequest.getHeaders());
        return exchange.mutate().request(mutatedRequest).build(); // 변경된 요청 반영
    }

    //        System.out.println(request.getHeaders());
    // Config할 inner class -> 설정파일에 있는 args
    @Getter
    @Setter
    public static class Config{
        private String headerName; // Authorization
        private String granted; // Bearer
    }
}