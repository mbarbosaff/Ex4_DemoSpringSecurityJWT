package com.example.myshop_security.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Utilizador de teste (em produção viria da base de dados)
        if ("admin".equals(username)) {
            return new User("admin",
                    new BCryptPasswordEncoder().encode("password"),
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("Utilizador não encontrado: " + username);
        }
    }
}
