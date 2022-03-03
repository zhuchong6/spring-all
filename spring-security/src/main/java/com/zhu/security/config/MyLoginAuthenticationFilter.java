package com.zhu.security.config;

import com.fasterxml.jackson.core.JsonParser;
import com.zhu.security.utils.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;

/**
 * @author zhuchong
 */
@Slf4j
public class MyLoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    public MyLoginAuthenticationFilter() {
        //直接使用父类的配置
        super();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //只支持post提交
        if (!request.getMethod().equals(HttpMethod.POST.name())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        UsernamePasswordAuthenticationToken unAuthenticaiton = null;
        try {
            Map<String, String> map = getStringStringMap(request);
            String username = map.get("username").trim();
            String password = map.get("password").trim();
            //创建一个未认证的Authentication
            unAuthenticaiton = new UsernamePasswordAuthenticationToken(username, password);
        }catch (Exception e){
            log.error("解析错误:{}", e.getMessage());
        }
        return getAuthenticationManager().authenticate(unAuthenticaiton);
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
        Map<String, String> map = parse.readValueAs(Map.class);
        return map;
    }


}
