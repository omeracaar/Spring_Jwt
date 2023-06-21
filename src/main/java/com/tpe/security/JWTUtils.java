package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;

import java.util.Date;

public class JWTUtils {

    //hash(abc)-->asdrewijgl-->abc ye donusturulemez--tek yonlu sifreleme
    //jwt token:header + payload(userla ilgili bilgiler) + signature(secret ile imza)

    private long jwtExpirationTime=86400000;//24*60*60*1000

    private String secretKey="techpro";

    //1-JWT token generate
    public String generateToken(Authentication authentication){

        UserDetailsImpl userDetails= (UserDetailsImpl) authentication.getPrincipal();//login olmus user(authenticated)

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())//system.currentMillis()
                .setExpiration(new Date(new Date().getTime()+jwtExpirationTime))
                .signWith(SignatureAlgorithm.HS512,secretKey)//hashleme ile tek yonlu sifreleme, karsilastirmada kullanilir
                .compact();//ayar
    }


    //2-JWT token validate
    public boolean validateToken(String token){

        try {
            Jwts.parser()//ayrıştırıcı
                    .setSigningKey(secretKey)//bu anahtar ile karşılaştır
                    .parseClaimsJws(token);//imzalar uyumlu ise, JWT geçerli

            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }


    //3-JWT tokendan username alma
    public String getUsernameFromJwtToken(String token){
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)//doğrulanmış tokenın claimslerini döndürür
                .getBody()
                .getSubject();//username
    }


}
