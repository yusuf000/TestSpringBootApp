package com.example.TestSpringBootApp.security;



import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.example.TestSpringBootApp.dataModel.Role;
import com.example.TestSpringBootApp.dataModel.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Created by sivakumar on 2/5/2018.
 */
public class LoggedUser implements UserDetails {

    private User user;

    private Long companyId;

    public LoggedUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (final Role privilege : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(privilege.getRole()));
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }


    public User getUser() {
        return this.user;
    }
}
