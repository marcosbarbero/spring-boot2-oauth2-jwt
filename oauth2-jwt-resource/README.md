Resource Server JWT
---

The resource server hosts the [HTTP resources](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Identifying_resources_on_the_Web) 
in which can be a document a photo or something else, in our case it will be a REST API protected by OAuth2.

## Dependencies

```xml
   <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
           
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security.oauth.boot</groupId>
            <artifactId>spring-security-oauth2-autoconfigure</artifactId>
            <version>2.1.2.RELEASE</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>

        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.6</version>
        </dependency>                
    </dependencies>
```

## Defining our protected API

The code bellow defines the endpoint `/me` which returns the `Principal` object and it requires the authenticated 
user to have the `ROLE_USER` to access. 

```java
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/me")
public class UserController {

    @GetMapping
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<Principal> get(final Principal principal) {
        return ResponseEntity.ok(principal);
    }

}
```

The `@PreAuthorize` annotation validates whether the user has the given role prior to execute the code, to make it work
it's necessary to enable the `prePost` annotations, to do so add the following class:

```java
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

}
```

The important part here is the `@EnableGlobalMethodSecurity(prePostEnabled = true)` annotation, the `prePostEnabled` flag
is set to `false` by default.

## Resource Server Configuration

To decode the `JWT` token it will be necessary to use the `public key` from the self-signed certificated used on the
[Authorization Server](../oauth2-jwt-server) to sign the token, to do so let's first create a `@ConfigurationProperties`
class to bind the configuration properties.

```java
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties("security")
public class SecurityProperties {

    private JwtProperties jwt;

    public JwtProperties getJwt() {
        return jwt;
    }

    public void setJwt(JwtProperties jwt) {
        this.jwt = jwt;
    }

    public static class JwtProperties {

        private Resource publicKey;

        public Resource getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(Resource publicKey) {
            this.publicKey = publicKey;
        }
    }

}
```

Use the following command to export the `public key` from the generated JKS: 

````bash
$ keytool -list -rfc --keystore keystore.jks | openssl x509 -inform pem -pubkey -noout
````

A sample response look like this:

```bash
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmWI2jtKwvf0W1hdMdajc
h+mFx9FZe3CZnKNvT/d0+2O6V1Pgkz7L2FcQx2uoV7gHgk5mmb2MZUsy/rDKj0dM
fLzyXqBcCRxD6avALwu8AAiGRxe2dl8HqIHyo7P4R1nUaea1WCZB/i7AxZNAQtcC
cSvMvF2t33p3vYXY6SqMucMD4yHOTXexoWhzwRqjyyC8I8uCYJ+xIfQvaK9Q1RzK
Rj99IRa1qyNgdeHjkwW9v2Fd4O/Ln1Tzfnk/dMLqxaNsXPw37nw+OUhycFDPPQF/
H4Q4+UDJ3ATf5Z2yQKkUQlD45OO2mIXjkWprAmOCi76dLB2yzhCX/plGJwcgb8XH
EQIDAQAB
-----END PUBLIC KEY-----
```

Copy it to a `public.txt` file and place it at `/src/main/resources` and then configure your `application.yml` pointing
to this file:

```yaml
security:
  jwt:
    public-key: classpath:public.txt
```

Now let's add the Spring's configuration for the resource server.

```java
import org.apache.commons.io.IOUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

@Configuration
@EnableResourceServer
@EnableConfigurationProperties(SecurityProperties.class)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final String ROOT_PATTERN = "/**";

    private final SecurityProperties securityProperties;

    private TokenStore tokenStore;

    public ResourceServerConfiguration(final SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
        resources.tokenStore(tokenStore());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, ROOT_PATTERN).access("#oauth2.hasScope('read')")
                .antMatchers(HttpMethod.POST, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PATCH, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PUT, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.DELETE, ROOT_PATTERN).access("#oauth2.hasScope('write')");
    }

    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        return tokenServices;
    }

    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setVerifierKey(getPublicKeyAsString());
        return converter;
    }

    private String getPublicKeyAsString() {
        try {
            return IOUtils.toString(securityProperties.getJwt().getPublicKey().getInputStream(), UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
```

The important part of this configuration are the three `@Bean`s: `JwtAccessTokenConverter`, `TokenStore` and `DefaultTokenServices`:
  - The `JwtAccessTokenConverter` uses the JKS `public key`.
  - The `JwtTokenStore` uses the `JwtAccessTokenConverter` to read the tokens.
  - The `DefaultTokenServices` uses the `JwtTokenStore` to persist the tokens.