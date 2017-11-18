package com.geeksoverflow.security.jwt.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URL;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.geeksoverflow.security.jwt.token.JwtAuthenticationToken;
import com.geeksoverflow.security.jwt.token.RawAccessJwtToken;
import com.geeksoverflow.security.jwt.token.TokenExtractor;

import io.jsonwebtoken.ExpiredJwtException;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 5/11/17
 */
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationFailureHandler failureHandler;
    private final TokenExtractor tokenExtractor;
    private final AuthenticationSuccessHandler successHandler;
    
    private static Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationProcessingFilter.class);

    @Autowired
    public JwtTokenAuthenticationProcessingFilter(	AuthenticationSuccessHandler successHandler,
    												AuthenticationFailureHandler failureHandler,
    												TokenExtractor tokenExtractor, RequestMatcher matcher) {
        super(matcher);
        this.failureHandler = failureHandler;
        this.tokenExtractor = tokenExtractor;
        this.successHandler = successHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
    	logger.info("attemptAuthentication");

        String tokenPayload = request.getHeader("X-Authorization");

        logger.info("tokenPayload from header::"+tokenPayload);

        if(tokenPayload == null || tokenPayload.length() == 0) {
        	Cookie[] cookies = request.getCookies();
        	
        	if (cookies != null) {
        		for (Cookie cookie : cookies) {
        			if (cookie.getName().equals("jwt-token")) {
        				tokenPayload = "Bearer "+cookie.getValue();
        				break;
        			}
        		}
        	}

        }
        
        logger.info("URL"+request.getHeader("Referer"));
        
        if( (tokenPayload == null || tokenPayload.length() == 0) && (request.getHeader("Referer") !=null && request.getHeader("Referer").contains("jwt-token="))) {
        	tokenPayload = "Bearer "+request.getHeader("Referer").substring(request.getHeader("Referer").indexOf("jwt-token=")+10);
        }
        
        logger.info("jwt-token ::"+tokenPayload);

        if(tokenPayload == null || tokenPayload.length() == 0) {
        	redirectToLoginApp(request, response);
        	return null;
        }

        Cookie ck = new Cookie("jwt-token", tokenPayload.replaceAll("Bearer ", "").trim());
        response.addCookie(ck);

        RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(tokenPayload));
        
        try{
        	Authentication authentication =  getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
        	return authentication;
        }catch(BadCredentialsException | ExpiredJwtException e) {
        	redirectToLoginApp(request, response);
        }

    	return null;
    }

    private void redirectToLoginApp(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie cookie = new Cookie("app-url", request.getRequestURL().toString());
        response.addCookie(cookie);

    	response.setStatus(HttpServletResponse.SC_FOUND);
    	response.setHeader("redirectURL", "https://www.wavemakeronline.com/run-2ty9qdjzpt/LoginApp?appURL="+request.getRequestURL());
    	logger.info("redirecting "+"https://www.wavemakeronline.com/run-2ty9qdjzpt/LoginApp/#/Main?appURL="+request.getRequestURL());
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
    	SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}