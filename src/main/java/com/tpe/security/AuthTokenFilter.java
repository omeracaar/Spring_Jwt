package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JWTUtils jwtUtils;

    //token filtreliyeceğiz, requestten tokenı almamız gerekiyor.
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token=parseJwt(request);

        try {
            if(token!=null && jwtUtils.validateToken(token)){

                String username=jwtUtils.getUsernameFromJwtToken(token);//login olan userın username
                UserDetails userDetails =userDetailsService.loadUserByUsername(username);//login olan user

                //login olan user ı security conntexte koymak için authentication objesi oluşturma
                UsernamePasswordAuthenticationToken authenticated=
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,//password
                                userDetails.getAuthorities());
                //login olan user ı security conntexte koyma
                SecurityContextHolder.getContext().setAuthentication(authenticated);


            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request,response);

    }


    //requestten tokenı almamız gerekiyor.
    //token: Bearer eyrlkfgdlkmfdlşfgRTU65

    private String parseJwt(HttpServletRequest request){

        String header=request.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7);
        }
        return null;
    }





}