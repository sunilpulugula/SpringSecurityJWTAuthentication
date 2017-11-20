package com.geeksoverflow.security.jwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
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
    private final String loginAppUrl;

    private static Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationProcessingFilter.class);

    @Autowired
    public JwtTokenAuthenticationProcessingFilter(	AuthenticationSuccessHandler successHandler,
    												AuthenticationFailureHandler failureHandler,
    												TokenExtractor tokenExtractor, 
    												String loginAppUrl,
    												RequestMatcher matcher) {
        super(matcher);
        this.failureHandler = failureHandler;
        this.tokenExtractor = tokenExtractor;
        this.successHandler = successHandler;
        this.loginAppUrl = loginAppUrl;
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = getJWTToken(request, response);

        if(jwtToken != null && jwtToken.length() > 0) {
			request.setAttribute("jwt-token", jwtToken);
            super.doFilter(request, response, chain);        	
        } else {
        	redirectToLoginApp(request, response);
        }

    }

    private String getJWTToken(HttpServletRequest request, HttpServletResponse response) {
    	String tokenPayload = request.getHeader("X-Authorization");

    	if(tokenPayload != null && tokenPayload.length() == 0) {
            logger.info("tokenPayload from header::"+tokenPayload);
            return tokenPayload;
    	}

        if((tokenPayload == null || tokenPayload.length() == 0) && request.getParameter("jwt-token") != null) {
        	tokenPayload = "Bearer " +request.getParameter("jwt-token");
        }

    	if(tokenPayload != null && tokenPayload.length() == 0) {
            logger.info("tokenPayload from param::"+tokenPayload);
            return tokenPayload;
    	}

        if(tokenPayload == null || tokenPayload.length() == 0) {
        	tokenPayload = getJWTTokenFromCookie(request);
        }

        if(tokenPayload != null && tokenPayload.length() == 0) {
            logger.info("tokenPayload from cookie::"+tokenPayload);
            return tokenPayload;
    	}

        if( (tokenPayload == null || tokenPayload.length() == 0) && (request.getHeader("Referer") !=null && request.getHeader("Referer").contains("jwt-token="))) {
        	tokenPayload = "Bearer "+request.getHeader("Referer").substring(request.getHeader("Referer").indexOf("jwt-token=")+10);
        }
        
        logger.info("tokenPayload::"+tokenPayload);

        return tokenPayload;
    }

    private String getJWTTokenFromCookie(HttpServletRequest request) {
    	Cookie[] cookies = request.getCookies();
    	
    	if (cookies != null) {
    		for (Cookie cookie : cookies) {
    			if (cookie.getName().equals("jwt-token")) {
    				return "Bearer "+cookie.getValue();
    			}
    		}
    	}
    	
    	return null;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
		String tokenPayload = request.getAttribute("jwt-token").toString();

		if(getJWTTokenFromCookie(request) == null) {
			Cookie ck = new Cookie("jwt-token", tokenPayload.replaceAll("Bearer ", "").trim());
	        response.addCookie(ck);
		}

        RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(tokenPayload));
        
        try{
        	return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
        }catch(BadCredentialsException | ExpiredJwtException e) {
        	redirectToLoginApp(request, response);
        }

    	return null;
    }

    private void redirectToLoginApp(HttpServletRequest request, HttpServletResponse response) throws IOException {
    	response.setStatus(HttpServletResponse.SC_FOUND);
    	response.setHeader("redirectURL", loginAppUrl+"?redirect_to="+request.getRequestURL());
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