package com.example.dnsautomation.controller;

import com.example.dnsautomation.dto.DnsCheckRequest;
import com.example.dnsautomation.dto.DnsCheckResponse;
import com.example.dnsautomation.service.DnsCheckFacade;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dns")
public class DnsCheckApiController {

    private final DnsCheckFacade dnsCheckFacade;

    public DnsCheckApiController(DnsCheckFacade dnsCheckFacade) {
        this.dnsCheckFacade = dnsCheckFacade;
    }

    @PostMapping("/check")
    public ResponseEntity<DnsCheckResponse> check(@RequestBody DnsCheckRequest request) {
        DnsCheckResponse response = dnsCheckFacade.check(request);
        return ResponseEntity.ok(response);
    }
}
