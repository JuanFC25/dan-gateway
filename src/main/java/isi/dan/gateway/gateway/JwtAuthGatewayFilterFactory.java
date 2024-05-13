package isi.dan.gateway.gateway;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    private final DiscoveryClient discoveryClient;
    private final RestTemplate restTemplate;
    private final String AUTH_PATH_SUFFIX = "/api/auth/validate";

    public JwtAuthGatewayFilterFactory(DiscoveryClient discoveryClient, RestTemplate restTemplate) {
        super(Config.class);
        this.discoveryClient = discoveryClient;
        this.restTemplate = restTemplate;
    }

    // 401 any request without a valid token.
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = extractToken(exchange.getRequest());

            if(token == null || token.trim().isEmpty()){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // get ms-user, if unavaiable return status 503
            // descomentar para eureka
            // List<ServiceInstance> instances = discoveryClient.getInstances("MS-Usuarios");
            // if (instances.isEmpty()) {
            //     exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            //     return exchange.getResponse().setComplete();
            // }

            // String authServiceUri = instances.get(0).getUri().toString() + AUTH_PATH_SUFFIX;
            String authServiceUri = "http://ms-usuarios:8080" + AUTH_PATH_SUFFIX;
            

            // now we can validate the token
            // by calling validateToken with the auth uri
            if(!validateTokenWithAuthService(token, authServiceUri)){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            //at this point the request (should)have authorization..
            // allow the gateway to do its job
            return chain.filter(exchange);
            //
        };
    }

    private String extractToken(ServerHttpRequest request) {
        List<String> authorizationHeaders = request.getHeaders().get("Authorization");
        if (authorizationHeaders != null && !authorizationHeaders.isEmpty()) {
            String authorizationHeader = authorizationHeaders.get(0);
            if (authorizationHeader.startsWith("Bearer ")) {
                return authorizationHeader.substring(7);
            }
        }
        return null;
    }

    private boolean validateTokenWithAuthService(String token, String authUri) {
        Map<String, String> tokenObejct = new HashMap<String, String>();
        tokenObejct.put("token", token);

        ResponseEntity<String> responseEntity;
        try{

            responseEntity = restTemplate.postForEntity(authUri, tokenObejct, String.class);
        } catch (HttpClientErrorException e){
            return e.getStatusCode().equals(HttpStatus.OK);
        } catch (Exception e){
            return false;
        }

        return responseEntity.getStatusCode().equals(HttpStatus.OK);
    }

    public static class Config {  

        // useful!
    }
}

