Centralized Authorization with JWT using Spring Boot 2
---

>Published on http://blog.marcosbarbero.com/centralized-authorization-jwt-spring-boot2/

This guide walks through the process to create a centralized authentication and authorization server with Spring Boot 2, 
a demo resource server will also be provided.

>If you're not familiar with OAuth2 I recommend this [read](https://www.oauth.com/).

## Pre-req
 
 - [JDK 1.8](https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
 - Text editor or your favorite IDE
 - [Maven 3.0+](https://maven.apache.org/download.cgi)

## Implementation Overview

For this project we'll be using [Spring Security 5](https://spring.io/projects/spring-security) through Spring Boot.
If you're familiar with the earlier versions this [Spring Boot Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-2.0-Migration-Guide#oauth2)
might be useful.

## OAuth2 Terminology

  - **Resource Owner**
    - The user who authorizes an application to access his account. The access is limited to the `scope`.
  - **Resource Server**:
    -  A server that handles authenticated requests after the `client` has obtained an `access token`.
  - **Client**
    - An application that access protected resources on behalf of the resource owner.
  - **Authorization Server**
    - A server which issues access tokens after successfully authenticating a `client` and `resource owner`, and authorizing the request.
  - **Access Token**
    - A unique token used to access protected resources
  - **Scope**
    - A Permission
  - **JWT**
    - JSON Web Token is a method for representing claims securely between two parties as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519)
  - **Grant type**
    - A `grant` is a method of acquiring an access token. 
    - [Read more about grant types here](https://oauth.net/2/grant-types/)

### Authorization Server

To build our `Auth Server` we'll be using [Spring Security 5.x](https://spring.io/projects/spring-security) through 
[Spring Boot 2.0.x](https://spring.io/projects/spring-boot).

#### Dependencies

You can go to [start.spring.io](https://start.spring.io/) and generate a new project and then add the following dependencies:

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
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>

        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>		
    </dependencies>
```

#### Database

For the sake of this tutorial we'll be using [H2 Database](http://www.h2database.com/html/main.html).  
Here you can find a reference OAuth2 SQL schema required by Spring Security.

```sql
CREATE TABLE IF NOT EXISTS oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256) NOT NULL,
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4000),
  autoapprove VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_client_token (
  token_id VARCHAR(256),
  token BLOB,
  authentication_id VARCHAR(256) PRIMARY KEY,
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_access_token (
  token_id VARCHAR(256),
  token BLOB,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication BLOB,
  refresh_token VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_id VARCHAR(256),
  token BLOB,
  authentication BLOB
);

CREATE TABLE IF NOT EXISTS oauth_code (
  code VARCHAR(256), authentication BLOB
);
```

>Note: As this tutorial uses `JWT` not all the tables are required.

And then add the following entry

```sql
-- The encrypted client_secret it `secret`
INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, authorities, access_token_validity)
  VALUES ('clientId', '{bcrypt}$2a$10$vCXMWCn7fDZWOcLnIEhmK.74dvK1Eh8ae2WrWlhr2ETPLoxQctN4.', 'read,write', 'password,refresh_token,client_credentials', 'ROLE_CLIENT', 300);
```

>The `client_secret` above was generated using [bcrypt](https://en.wikipedia.org/wiki/Bcrypt).  
>The prefix `{bcrypt}` is required because we'll using Spring Security 5.x's new feature of [DelegatingPasswordEncoder](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#pe-dpe).

Bellow here you can find the `User` and `Authority` reference SQL schema used by Spring's `org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl`.

```sql
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(256) NOT NULL,
  password VARCHAR(256) NOT NULL,
  enabled TINYINT(1),
  UNIQUE KEY unique_username(username)
);

CREATE TABLE IF NOT EXISTS authorities (
  username VARCHAR(256) NOT NULL,
  authority VARCHAR(256) NOT NULL,
  PRIMARY KEY(username, authority)
);
```

Same as before add the following entries for the user and its authority.

```sql
-- The encrypted password is `pass`
INSERT INTO users (id, username, password, enabled) VALUES (1, 'user', '{bcrypt}$2a$10$cyf5NfobcruKQ8XGjUJkEegr9ZWFqaea6vjpXWEaSqTa2xL9wjgQC', 1);
INSERT INTO authorities (username, authority) VALUES ('user', 'ROLE_USER');
```

#### Spring Security Configuration

Add the following Spring configuration class.

```java

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final DataSource dataSource;

    private PasswordEncoder passwordEncoder;
    private UserDetailsService userDetailsService;

    public WebSecurityConfiguration(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        if (passwordEncoder == null) {
            passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
        return passwordEncoder;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        if (userDetailsService == null) {
            userDetailsService = new JdbcDaoImpl();
            ((JdbcDaoImpl) userDetailsService).setDataSource(dataSource);
        }
        return userDetailsService;
    }

}
```

Quoting from [Spring Blog](https://spring.io/blog/2013/07/03/spring-security-java-config-preview-web-security#websecurityconfigureradapter):

>The @EnableWebSecurity annotation and WebSecurityConfigurerAdapter work together to provide web based security.

If you are using Spring Boot the `DataSource` object will be auto-configured and you can just inject it to the class instead of defining it yourself.
it needs to be injected to the `UserDetailsService` in which will be using the provided `JdbcDaoImpl` provided by Spring Security, if necessary 
you can replace this with your own implementation.

As the Spring Security's `AuthenticationManager` is required by some auto-configured Spring `@Bean`s it's necessary to
override the `authenticationManagerBean` method and annotate is as a `@Bean`.

The `PasswordEncoder` will be handled by `PasswordEncoderFactories.createDelegatingPasswordEncoder()` in which handles a
few of password encoders and delegates based on a prefix, in our example we are prefixing the passwords with `{bcrypt}`.

### Authorization Server Configuration

The authorization server validates the `client` and `user` credentials and provides the tokens, in this tutorial we'll be
generating `JSON Web Tokens` a.k.a `JWT`.

To sign the generated `JWT` tokens we'll be using a self-signed certificate and to do so before we start with the 
Spring Configuration let's create a `@ConfigurationProperties` class to bind our configuration properties.

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

        private Resource keyStore;
        private String keyStorePassword;
        private String keyPairAlias;
        private String keyPairPassword;

        public Resource getKeyStore() {
            return keyStore;
        }

        public void setKeyStore(Resource keyStore) {
            this.keyStore = keyStore;
        }

        public String getKeyStorePassword() {
            return keyStorePassword;
        }

        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        public String getKeyPairAlias() {
            return keyPairAlias;
        }

        public void setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
        }

        public String getKeyPairPassword() {
            return keyPairPassword;
        }

        public void setKeyPairPassword(String keyPairPassword) {
            this.keyPairPassword = keyPairPassword;
        }
    }
}
```

Add the following Spring configuration class.

```java
import com.marcosbarbero.lab.sec.oauth.jwt.config.props.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;

@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityProperties securityProperties;

    private JwtAccessTokenConverter jwtAccessTokenConverter;
    private TokenStore tokenStore;

    public AuthorizationServerConfiguration(final DataSource dataSource, final PasswordEncoder passwordEncoder,
                                            final AuthenticationManager authenticationManager, final SecurityProperties securityProperties) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.securityProperties = securityProperties;
    }

    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore,
                                              final ClientDetailsService clientDetailsService) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAuthenticationManager(this.authenticationManager);
        return tokenServices;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        if (jwtAccessTokenConverter != null) {
            return jwtAccessTokenConverter;
        }

        SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
        KeyPair keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

        jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(this.dataSource);
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(this.authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenStore(tokenStore());
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.passwordEncoder(this.passwordEncoder).tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
        return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(), jwtProperties.getKeyPairPassword().toCharArray());
    }

    private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
        return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
    }
}
```

In the class above you'll find all the required Spring `@Bean`s for `JWT`. 
The most important `@Bean`s are: `JwtAccessTokenConverter`, `JwtTokenStore` and the `DefaultTokenServices`.

The `JwtAccessTokenConverter` uses the self-signed certificate to sign the generated tokens.  
The `JwtTokenStore` implementation that just reads data from the tokens themselves. Not really a store since it 
never persists anything and it uses the `JwtAccessTokenConverter` to generate and read the tokens.  
The `DefaultTokenServices` uses the `TokenStore` to persist the tokens.

>Follow this guide [to generate a self-signed certificate](https://dzone.com/articles/creating-self-signed-certificate).

After generating your self-signed certificate configure it on your `application.yml`.

```yaml
security:
  jwt:
    key-store: classpath:keystore.jks
    key-store-password: letmein
    key-pair-alias: mytestkey
    key-pair-password: changeme
```

### Resource Server Configuration

[Follow this link](../resource-server-jwt).

### Testing all together

To test all together we need to spin up the `Authorization Server` and the `Resource Server` as well, in my setup it will be
running on port `9000` and `9100` accordingly.

#### Generating the token

```bash
$ curl -u clientId:secret -X POST localhost:9000/oauth/token\?grant_type=password\&username=user\&password=pass

{
  "access_token" : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDgxODk0NDUsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiYjFjYWQ3MTktZTkwMS00Njk5LTlhOWEtYTIwYzk2NDM5NjAzIiwiY2xpZW50X2lkIjoiY2xpZW50SWQiLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXX0.LkQ3KAj2kPY7yKmwXlhIFaHtt-31mJGWPb-_VpC8PWo9IBUpZQxg76WpahBJjet6O1ICx8b5Ab2CxH7ErTl0tL1jk5VZ_kp66E9E7bUQn-C09CY0fqxAan3pzpGrJsUvcR4pzyzLoRCuAqVRF5K2mdDQUZ8NaP0oXeVRuxyRdgjwMAkQGHpFC_Fk-7Hbsq2Y0GikD0UdkaH2Ey_vVyKy5aj3NrAZs62KFvQfSbifxd4uBHzUJSkiFE2Cx3u1xKs3W2q8MladwMwlQmWJROH6lDjQiybUZOEhJaktxQYGAinScnm11-9WOdaqohcr65PAQt48__rMRi0TUgvsxpz6ow",
  "token_type" : "bearer",
  "refresh_token" : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsicmVhZCIsIndyaXRlIl0sImF0aSI6ImIxY2FkNzE5LWU5MDEtNDY5OS05YTlhLWEyMGM5NjQzOTYwMyIsImV4cCI6MTU1MDc4MTE0NSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6Ijg2OWFjZjM2LTJiODAtNGY5Ni04MzUwLTA5NTgyMzE3NTAzMCIsImNsaWVudF9pZCI6ImNsaWVudElkIn0.TDQwUNb627-f0-Cjn1vWZXFpzZSGpeKZq85ivA9zY_atOXM2WfjOxTLE6phnNLevjLSNAGrx1skm_sx6leQlrrmDi36nwiR7lvhv8xMbn1DkF5KaoWPhldW7GHsSIiauMu_cJ5Kmq89ZOEOlxYoXlLwfWYo75ISkKNYqko98yDogGrRAJxtc1aKIBLypLchhoCf8w43efd11itwvBdaLIb5ACfN30kztUqQtbeL8voQP6tOsRZbCgbOOKMTulOCRyBvaora4GJDV2qdvXdCUT-kORKDj9liqt2ae7OJzb2FuuXCGqBUrxYYK-H-wdwh7XFkXVe74Lev9YDUbyEmDHg",
  "expires_in" : 299,
  "scope" : "read write",
  "jti" : "b1cad719-e901-4699-9a9a-a20c96439603"
}
```

#### Accessing the resource

Now that you have generated the token copy the `access_token` and add it to the request on the `Authorization` 
HTTP Header, e.g: 

```bash
curl localhost:9100/me -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDgxODk0NDUsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiYjFjYWQ3MTktZTkwMS00Njk5LTlhOWEtYTIwYzk2NDM5NjAzIiwiY2xpZW50X2lkIjoiY2xpZW50SWQiLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXX0.LkQ3KAj2kPY7yKmwXlhIFaHtt-31mJGWPb-_VpC8PWo9IBUpZQxg76WpahBJjet6O1ICx8b5Ab2CxH7ErTl0tL1jk5VZ_kp66E9E7bUQn-C09CY0fqxAan3pzpGrJsUvcR4pzyzLoRCuAqVRF5K2mdDQUZ8NaP0oXeVRuxyRdgjwMAkQGHpFC_Fk-7Hbsq2Y0GikD0UdkaH2Ey_vVyKy5aj3NrAZs62KFvQfSbifxd4uBHzUJSkiFE2Cx3u1xKs3W2q8MladwMwlQmWJROH6lDjQiybUZOEhJaktxQYGAinScnm11-9WOdaqohcr65PAQt48__rMRi0TUgvsxpz6ow"

{
  "authorities" : [ {
    "authority" : "ROLE_GUEST"
  } ],
  "details" : {
    "remoteAddress" : "127.0.0.1",
    "sessionId" : null,
    "tokenValue" : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDgyMzcxNDEsInVzZXJfbmFtZSI6Imd1ZXN0IiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9HVUVTVCJdLCJqdGkiOiIzNDk1ODE1MC0wOGJkLTQwMDYtYmNhMC1lM2RkYjAxMGU2NjUiLCJjbGllbnRfaWQiOiJjbGllbnRJZCIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSJdfQ.WUwAh-aKgh_Bqk-a9ijw67EI6H8gFrb3D_WdwlEcITskIybhacHjT6E7cUXjdBT7GCRvvJ-yxzFJIQyI6y0t61SInpqVG2GlAwtTxR5reG0e4ZtcKoq2rbQghK8hWenGplGT31kjDY78zZv-WqCAc0-MM4cC06fTXFzdhsdueY789lCasSD4WMMC6bWbN098lHF96rMpCdlW13EalrPgcKeuvZtUBrC8ntL8Bg3LRMcU1bFKTRAwlVxw1aYyqeEN4NSxkiSgQod2dltA-b3c15L-fXoOWNGnPB68hqgK48ymuemRQTSg3eKmHFAQdDL6pxQ8_D_ZWAL3QhsKQVGDKg",
    "tokenType" : "Bearer",
    "decodedDetails" : null
  },
  "authenticated" : true,
  "userAuthentication" : {
    "authorities" : [ {
      "authority" : "ROLE_GUEST"
    } ],
    "details" : null,
    "authenticated" : true,
    "principal" : "guest",
    "credentials" : "N/A",
    "name" : "guest"
  },
  "credentials" : "",
  "principal" : "guest",
  "clientOnly" : false,
  "oauth2Request" : {
    "clientId" : "clientId",
    "scope" : [ "read", "write" ],
    "requestParameters" : {
      "client_id" : "clientId"
    },
    "resourceIds" : [ ],
    "authorities" : [ ],
    "approved" : true,
    "refresh" : false,
    "redirectUri" : null,
    "responseTypes" : [ ],
    "extensions" : { },
    "grantType" : null,
    "refreshTokenRequest" : null
  },
  "name" : "guest"
}
```
 
# Footnote
 - The code used for this tutorial can be found on [GitHub](https://github.com/marcosbarbero/spring-boot-n-cloud-playground/tree/master/security).
 - [OAuth 2.0](https://www.oauth.com/) 
 - [Spring Security Java Config Preview](https://spring.io/blog/2013/07/03/spring-security-java-config-preview-web-security)
 - [Spring Boot 2 - Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-2.0-Migration-Guide#authenticationmanager-bean)
 - [Spring - OAuth2 Developers Guide](https://projects.spring.io/spring-security-oauth/docs/oauth2.html)