package com.zhu.security.entity;

import lombok.Data;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;

/**
 * @author zhuchonbg
 */
@Data
public class SmsDetail implements UserDetails {
    private static final Log logger = LogFactory.getLog(User.class);

    private String password;

    private String username;

    private Set<GrantedAuthority> authorities;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

    /**
     * 手机号
     */
    private String phone;
    /**
     * 验证码
     */
    private String code;
}
