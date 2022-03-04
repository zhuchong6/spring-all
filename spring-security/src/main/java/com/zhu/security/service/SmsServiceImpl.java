package com.zhu.security.service;

import com.zhu.security.utils.CacheUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author zhuchong
 */
@Service(value = "smsService")
public class SmsServiceImpl implements UserService, UserDetailsService {

    public String getCode(String phone) throws UsernameNotFoundException {
        //这里就是通过phone去缓存中取数据
        String key = "sms"+phone;
        String code = CacheUtil.get(key);
        if(code == null){
            throw new UsernameNotFoundException("验证码不存在");
        }
        return code;
    }

    @Override
    public UserDetails loadUserByUsername(String phone) throws UsernameNotFoundException {
        //通过手机号查找用户
        if (!"131".equals(phone)) {
            throw new UsernameNotFoundException("找不到用户");
        }

        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN,ROLE_USER");
        String encode = new BCryptPasswordEncoder().encode("123");
        return new User("zhuchong", encode, grantedAuthorities);
    }
}
