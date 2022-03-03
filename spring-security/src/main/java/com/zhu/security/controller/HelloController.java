package com.zhu.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author zhuchong
 */
@RestController
public class HelloController {
    @GetMapping("/index")
    public String index(HttpServletRequest request){

        return "index";
    }

    @GetMapping("/hello")
    public String hello(HttpServletRequest request){
        return "hello";
    }
}
