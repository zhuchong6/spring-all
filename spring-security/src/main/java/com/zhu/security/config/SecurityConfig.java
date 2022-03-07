package com.zhu.security.config;

import com.zhu.security.utils.JsonUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * @author zhuchong
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationProvider myAuthenticationProvider;

    @Autowired
    private SmsAuthenticationProvider smsAuthenticationProvider;

    @Autowired
    private SmsRoleSecurityMetadataSource smsRoleSecurityMetadataSource;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SmsLoginAuthenticationFilter smsLoginAuthenticationFilter() throws Exception{
        SmsLoginAuthenticationFilter filter = new SmsLoginAuthenticationFilter();

        //对这个filter设置AuthenticationManager，取默认的ProviderManager
        filter.setAuthenticationManager(authenticationManagerBean());
        //设置成功的处理器，由于要返回json，所以进行一些处理
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            //登录成功时返回给前端的数据
            Map result = new HashMap();
            result.put("success", "sms登录成功");
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write(JsonUtil.jsonToString(result));
        });
        //设置失败的处理器，由于要返回json，所以进行一些处理
        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            Map result = new HashMap();

            if (exception instanceof UsernameNotFoundException) {
                result.put("fail", exception.getMessage());
            } else if (exception instanceof BadCredentialsException) {
                result.put("fail", "sms密码错误" + exception.getMessage());
            } else {
                result.put("fail", "sms其他异常");
            }
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write(JsonUtil.jsonToString(result));
        });

        return filter;
    }

    @Bean
    public MyLoginAuthenticationFilter myLoginAuthenticationFilter() throws Exception {
        MyLoginAuthenticationFilter filter = new MyLoginAuthenticationFilter();

        //对这个filter设置AuthenticationManager，取默认的
        filter.setAuthenticationManager(authenticationManagerBean());
        //设置成功的处理器，由于要返回json，所以进行一些处理
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            //登录成功时返回给前端的数据
            Map result = new HashMap();
            result.put("success", "登录成功");
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write(JsonUtil.jsonToString(result));
        });
        //设置失败的处理器，由于要返回json，所以进行一些处理
        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            Map result = new HashMap();

            if (exception instanceof UsernameNotFoundException) {
                result.put("fail", exception.getMessage());
            } else if (exception instanceof BadCredentialsException) {
                result.put("fail", "密码错误" + exception.getMessage());
            } else {
                result.put("fail", "其他异常");
            }
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write(JsonUtil.jsonToString(result));
        });
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //关闭跨域和csrf防护
        http.cors().and().csrf().disable();
        //对请求url进行防护
        http
//                .authorizeRequests()
//                .antMatchers("/index").hasRole("USER")
//                .antMatchers("hello").hasRole("admin")
//                .and()
                .authorizeRequests()
                //放行这些路径
                .antMatchers("/smsLogin","/verityCode","/login")
                .permitAll()
                .and()

                .authorizeRequests()
                .anyRequest().authenticated()
                //修改accessManager
                .accessDecisionManager(customizeAccessDecisionManager())
                //放入自定义的权限拦截器
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {

                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(smsRoleSecurityMetadataSource);
                        return object;
                    }
                })

                .and()
                .formLogin()
                .permitAll()

                .and()
                .logout()
                .permitAll()
                .logoutSuccessHandler((request, response, authentication) -> {
                    //登出成功时返回给前端的数据
                    Map result = new HashMap();
                    result.put("success", "注销成功");
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(JsonUtil.jsonToString(result));
                })
                .deleteCookies("JSESSIONID")

                .and()
                .exceptionHandling()
                .accessDeniedHandler((request, response, exception) -> {
                    //访问拒绝时返回给前端的数据
                    Map result = new HashMap();
                    result.put("success", "无权访问，need Authorities!!");
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(JsonUtil.jsonToString(result));
                })
                .authenticationEntryPoint((request, response, exception) -> {
                    //访问有权限url时进行拦截
                    Map result = new HashMap();
                    result.put("success", "需要登录!!");
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(JsonUtil.jsonToString(result));
                })
                .and()
                .sessionManagement()
                .maximumSessions(1)     //最多只能一个用户登录一个账号
                .expiredSessionStrategy(event -> {
                    //session策略的返回
                    Map result = new HashMap();
                    result.put("success", "您的账号在异地登录，建议修改密码!!");
                    HttpServletResponse response = event.getResponse();
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(JsonUtil.jsonToString(result));
                });
        //把filter添加到UsernamePasswordAuthenticationFilter这个过滤器位置
        http.addFilterAt(myLoginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(smsLoginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        //把自定义的AuthenticationProvider设置进去
        http.authenticationProvider(myAuthenticationProvider)
                .authenticationProvider(smsAuthenticationProvider);
    }

    private AccessDecisionManager customizeAccessDecisionManager() {

        List<AccessDecisionVoter<? extends Object>> decisionVoterList
                = Arrays.asList(
                new SmsRoleBasedVoter()
        );
        return new AffirmativeBased(decisionVoterList);
    }
}
