package com.zhu.security.config;

import com.fasterxml.jackson.core.JsonParser;
import com.zhu.security.utils.JsonUtil;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author zhuchong
 */
public class SmsLoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    Map<String,String> map= new HashMap<>();
    //定义短信接口的入参
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "userPhone";

    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "code";

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;

    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

    //定义短信接口的url和方法类型
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/smsLogin",
            "POST");

    public SmsLoginAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }


    public SmsLoginAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        //只支持post提交
        if (!request.getMethod().equals(HttpMethod.POST.name())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        //取出reqest的手机号
        String username = obtainUsername(request);
        username = (username != null) ? username : "";
        username = username.trim();
        //取出request的验证码
        String password = obtainPassword(request);
        password = (password != null) ? password : "";
        //创建一个自定义的Authentication对象
        SmsAuthenticationToken smsAuthenticationToken = new SmsAuthenticationToken(username, password);
        //把request的一些参数绑定到smsAuthenticationToken对象中，具体可以断点查看
        setDetails(request, smsAuthenticationToken);
        //调用AuthenticationManager的authenticate方法
        return this.getAuthenticationManager().authenticate(smsAuthenticationToken);
    }

    protected void setDetails(HttpServletRequest request, SmsAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    @Nullable
    protected String obtainPassword(HttpServletRequest request) throws IOException {
        return map.get(passwordParameter);
    }


    @Nullable
    protected String obtainUsername(HttpServletRequest request) throws IOException {
        getStringStringMap(request);
        return map.get(usernameParameter);
    }



    /**
     * 将request中的用户名、密码提取出来封装到map中
     * @param request
     * @return
     * @throws IOException
     */
    private Map<String, String> getStringStringMap(HttpServletRequest request) throws IOException {
        BufferedReader reader = request.getReader();
        StringBuilder builder = new StringBuilder();
        String line = reader.readLine();
        while (line != null) {
            builder.append(line);
            line = reader.readLine();
        }
        reader.close();

        String reqBody = builder.toString();

        JsonParser parse = JsonUtil.parse(reqBody);
        map = parse.readValueAs(Map.class);
        return map;
    }
}
