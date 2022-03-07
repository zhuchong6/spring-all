package com.zhu.security.config;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * @author by zhuhcong
 * @descr
 * @date 2022/3/8 01:47
 */
@Component
public final class SmsAuthorizationFilterManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 假设从数据库中加载
     */
    private final Map<String,String> urlRoleMap = new HashMap<String,String>(){{
        put("/open/**","ROLE_ANONYMOUS");
        put("/health","ROLE_ANONYMOUS");
        put("/restart","ROLE_ADMIN");
        put("/demo","ROLE_USER");
        put("/index", "ROLE_USER");
    }};


    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        HttpServletRequest request = object.getRequest();

        if(authentication.get() == null){
            return new AuthorizationDecision(false);
        }

        Collection<? extends GrantedAuthority> authorities = authentication.get().getAuthorities();

        if(authorities==null || authorities.size()==0){
            return new AuthorizationDecision(false);
        }

        for(GrantedAuthority grantedAuthority : authorities){
            String authority = grantedAuthority.getAuthority();
            String role = urlRoleMap.get(request.getRequestURI());
            boolean match = antPathMatcher.match(authority, role);
            if(match){
                return new AuthorizationDecision(true);
            }
        }
        return new AuthorizationDecision(false);

    }


    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }

}