package com.zhu.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author zhuchong
 */
@RestController
public class HelloController {


    @GetMapping("/index")
    @PreAuthorize("hasRole('USER')")
    public String index(HttpServletRequest request){
        return SecurityContextHolder.getContext().getAuthentication().toString();
    }

    @GetMapping("/hello")
    public String hello(HttpServletRequest request){
        return "hello";
    }
}
