package com.zhu.security.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * @author zhuchong
 */
public class JsonUtil {

    public static String jsonToString(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        String s = mapper.writeValueAsString(object);
        return s;
    }

    public static JsonParser parse(String s) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonParser parser = mapper.createParser(s);
        return parser;
    }
}
