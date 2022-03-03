package com.zhu.security.controller;

import com.zhu.security.utils.CacheUtil;
import com.zhu.security.utils.Result;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author zhuchong
 */
@RestController
public class SmsLoginController {

    @PostMapping("/verityCode")
    @ResponseBody
    Result login(@RequestBody Map<String, String> map) {
        String username = map.get("userPhone");
        //如果用户存在，发送验证码
        Boolean checkUserExist = true;
        if(checkUserExist){
            //假装是一个随机的字符串
            String code = "66666";
            CacheUtil.put("sms"+username,code);
            return Result.ok(code);
        }
        return Result.ok();
    }

}
