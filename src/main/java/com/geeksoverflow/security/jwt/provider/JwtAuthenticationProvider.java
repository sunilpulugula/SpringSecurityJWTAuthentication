package com.geeksoverflow.security.jwt.provider;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.geeksoverflow.security.jwt.factory.JwtSettings;
import com.geeksoverflow.security.jwt.model.UserContext;
import com.geeksoverflow.security.jwt.token.JwtAuthenticationToken;
import com.geeksoverflow.security.jwt.token.RawAccessJwtToken;
//import com.wavemaker.runtime.security.WMUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 5/11/17
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtSettings jwtSettings;
    
    private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationProvider.class);
    
    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();
		logger.info("rawAccessToken :"+rawAccessToken);
        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(jwtSettings.getTokenSigningKey());
        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get("scopes", List.class);
        List<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        UserContext context = UserContext.create(subject, authorities);

        logger.info("context :"+context.getUsername());
		return new UsernamePasswordAuthenticationToken(context.getUsername(), null,authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
