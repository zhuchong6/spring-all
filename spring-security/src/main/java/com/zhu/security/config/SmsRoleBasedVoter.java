package com.zhu.security.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author by zhuhcong
 * @descr 访问决策投票,参考系统默认实现类RoleVoter
 * @date 2022/3/7 20:29
 */
public class SmsRoleBasedVoter implements AccessDecisionVoter<Object> {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        if(authentication == null){
            return ACCESS_DENIED;
        }
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (ConfigAttribute attribute : attributes) {
            if(attribute.getAttribute() == null){
                continue;
            }
            if (this.supports(attribute)) {
                for (GrantedAuthority authority : authorities) {
                    if(attribute.getAttribute().equals(authority.getAuthority())){
                        return ACCESS_GRANTED;
                    }
                }
            }
        }
        return ACCESS_DENIED;
    }
}