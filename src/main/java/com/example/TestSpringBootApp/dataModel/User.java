package com.example.TestSpringBootApp.dataModel;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class User {
    private String username;
    private String password;
    private Set<Role> roles;

}
