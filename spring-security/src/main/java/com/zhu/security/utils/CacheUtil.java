package com.zhu.security.utils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CacheUtil {

    private static Map<String ,String> cache = new ConcurrentHashMap<>();


    public static void put(String key, String value){
        cache.putIfAbsent(key, value);
    }

    public static  String get(String key){
        //默认值null，代表找不带到
        return cache.getOrDefault(key, null);
    }

}
