package com.zhu.security.config;

import com.zhu.security.service.SmsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class SmsAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private SmsServiceImpl smsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsAuthenticationToken smsAuthenticationToken = (SmsAuthenticationToken) authentication;
        //请求参数获取的
        String unAuthenticationCode = authentication.getCredentials().toString();
        //从后台缓存获取的
        String authenticationCode = smsService.getCode(smsAuthenticationToken.getPrincipal().toString());
        if (authenticationCode == null) {
            throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        if (!unAuthenticationCode.equals(authenticationCode)) {
            throw new BadCredentialsException("AbstractUserDetailsAuthenticationProvider.badCredentials");
        }
        //验证通过，从数据库取user，填充到userDetails中
        UserDetails user = smsService.loadUserByUsername(smsAuthenticationToken.getPrincipal().toString());
        return createSuccessAuthentication(authentication, user);
    }

    private Authentication createSuccessAuthentication(Authentication authentication, UserDetails smsDetail) {
        //主要拼一个
        SmsAuthenticationToken authenticationToken = new SmsAuthenticationToken(smsDetail.getAuthorities(),
                smsDetail.getUsername(), smsDetail.getPassword());
        authenticationToken.setDetails(authentication.getDetails());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (SmsAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
