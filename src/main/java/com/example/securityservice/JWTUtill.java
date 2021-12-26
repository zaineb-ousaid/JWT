package com.example.securityservice;

public class JWTUtill {
    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEADER = "Authorization";
    public static final Long EXPIRE_ACCES_TOKEN = 2*60*1000L;
    public static final long EXPIRE_REFRESH_TOKEN = 15*60*1000L;
}
