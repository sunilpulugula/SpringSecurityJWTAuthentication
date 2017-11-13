package com.geeksoverflow.security.jwt.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.geeksoverflow.security.jwt.database.dao.UserDAO;
import com.geeksoverflow.security.jwt.database.model.Role;
import com.geeksoverflow.security.jwt.database.model.User;
import com.geeksoverflow.security.jwt.model.LocalUser;


/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 10/5/17
 */
@Service("userDetailsService")
public class LocalUserDetailsService implements UserDetailsService {

    @Autowired
    private UserDAO userDAO;

    @Override
    public LocalUser loadUserByUsername(final String userId) throws UsernameNotFoundException {
        User user = userDAO.get(userId);
        if (user == null) {
            throw new UsernameNotFoundException("Given userId does not exist in repo");
        }
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = buildSimpleGrantedAuthorities(user);
        return new LocalUser(user.getUserId(), user.getUserId(), user.getPassword(), user.getPhoneno(),user.getActive() == 1 ? true : false, true
                , true, true, simpleGrantedAuthorities);
    }

    private List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(final User user) {
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                simpleGrantedAuthorities.add(new SimpleGrantedAuthority(role.getName()));
            }
        }
        return simpleGrantedAuthorities;
    }

}
