package com.zhu.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;


@Controller
public class LoginController {

//    @Autowired
//    private UserService userService;

    @PostMapping("/login")
    @ResponseBody
    String login(@RequestBody Map<String , String> map) {
        String username = map.get("username");
        String password = map.get("password");


//        UserDetailsService userService = (UserDetailsService) this.userService;
//        UserDetails userDetails = userService.loadUserByUsername(username);
//        String password1 = userDetails.getPassword();
//        System.out.println(password1);
        return "login";
    }
}
