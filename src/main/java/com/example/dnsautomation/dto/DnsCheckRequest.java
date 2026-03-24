package com.example.dnsautomation.dto;

import java.util.List;

public record DnsCheckRequest(
        String domain,
        List<String> publicIps,
        String selector
) {}
