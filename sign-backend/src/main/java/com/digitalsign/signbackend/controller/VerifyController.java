/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.controller;


import com.digitalsign.signbackend.bean.VerifyFileRequest;
import com.digitalsign.signbackend.service.VerifyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 *
 * @author Chungnv
 */
@RestController

public class VerifyController {


    @Autowired
    VerifyService verifyService;

    @RequestMapping(value = "/verify", method = RequestMethod.POST)
    public ResponseEntity upload(@RequestBody VerifyFileRequest request) throws IOException, Exception {
        return ResponseEntity.ok(verifyService.verifyFile(request));


    }


}
