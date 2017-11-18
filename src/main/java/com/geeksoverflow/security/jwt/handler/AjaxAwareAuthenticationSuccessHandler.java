package com.geeksoverflow.security.jwt.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.geeksoverflow.security.jwt.factory.JwtTokenFactory;
import com.geeksoverflow.security.jwt.model.UserContext;
import com.geeksoverflow.security.jwt.token.JwtToken;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 5/11/17
 */
public class AjaxAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper mapper;
    private final JwtTokenFactory tokenFactory;
    
    private static Logger logger = LoggerFactory.getLogger(AjaxAwareAuthenticationSuccessHandler.class);

    @Autowired
    public AjaxAwareAuthenticationSuccessHandler(final ObjectMapper mapper, final JwtTokenFactory tokenFactory) {
        this.mapper = mapper;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
    	User details = (User) authentication.getPrincipal();

    	logger.info("getUsername:"+details.getUsername());
    	logger.info("getAuthorities:"+details.getAuthorities());

		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.addAll(details.getAuthorities());

		UserContext userContext = UserContext.create(details.getUsername(), authorities);
		logger.info("userContext"+userContext);
        
		JwtToken accessToken = tokenFactory.createAccessJwtToken(userContext);
		logger.info("accessToken"+accessToken);
        
		JwtToken refreshToken = tokenFactory.createRefreshToken(userContext);
		logger.info("refreshToken"+refreshToken);
        
		Map<String, String> tokenMap = new HashMap<String, String>();
        tokenMap.put("token", accessToken.getToken());
        tokenMap.put("refreshToken", refreshToken.getToken());

        response.setStatus(HttpStatus.FOUND.value());

        Cookie cookie = new Cookie("jwt-token", accessToken.getToken());
        response.addCookie(cookie);

        clearAuthenticationAttributes(request);
        String url = ""; 
        
    	Cookie[] cookies = request.getCookies();
    	
    	if (cookies != null) {
    		for (Cookie ck : cookies) {
    			if (ck.getName().equals("referrerURL")) {
    				url  = ck.getValue();
    				url += "?jwt-token="+accessToken.getToken();
    				break;
    			}
    		}
    	}
    	
    	logger.info("URL from cookie :"+url);

    	if(url.length() == 0) {
	    	url = java.net.URLDecoder.decode(request.getHeader("referer"),"UTF-8");
	        if(url.contains("service=")) url = url.substring(url.indexOf("service=")+8);
	        logger.info("redirection url before:"+url);
	        if(url.contains("j_spring_cas_security_check")) url = url.substring(0, url.indexOf("/j_spring_cas_security_check"));
    	}

    	logger.info("calling redirection url :"+url);

    	response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("X-WM-X-Authorization", "Bearer "+accessToken.getToken());
        response.setHeader("redirectURL",url);
    	response.setStatus(302);
        response.sendRedirect(url);
    }

    /**
     * Removes temporary authentication-related data which may have been stored
     * in the session during the authentication process..
     *
     */
    protected final void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}