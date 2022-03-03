package com.zhu.security.utils;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public final class Result<T> implements Serializable {
    private static final long serialVersionUID = 1L;

    private Long code;

    private String message;

    private T data;



    public static <T> Result<T> ok(long code, T data) {
        return new Result(code, (String)null,  data);
    }


    public static <T> Result<T> ok(T data) {
        return ok(200, data);
    }

    public static <T> Result<T> ok() {
        return ok(200, null);
    }

}