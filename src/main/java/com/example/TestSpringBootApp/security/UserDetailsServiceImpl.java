package com.example.TestSpringBootApp.security;



import com.example.TestSpringBootApp.Util.Util;
import com.example.TestSpringBootApp.dataModel.Role;
import com.example.TestSpringBootApp.dataModel.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Created by sivakumar on 18/3/2018.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        User activeUserInfo = null;
        for (int i = 0; i < Util.users.length; i++) {
            if(userName.equals(Util.users[i])) {
                Set<Role> role = new HashSet<>();
                role.add(Role.builder().role(Util.role[i]).build());
                activeUserInfo = User.builder().username(userName).password(Util.pass[i]).roles(role).build();
            }
        }
        if (activeUserInfo == null) {
            throw new UsernameNotFoundException("Could not locate user with username: " + userName);
        }
        return new LoggedUser(activeUserInfo);
    }
}
