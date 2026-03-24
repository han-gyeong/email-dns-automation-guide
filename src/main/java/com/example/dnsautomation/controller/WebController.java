package com.example.dnsautomation.controller;

import com.example.dnsautomation.dto.DnsCheckRequest;
import com.example.dnsautomation.dto.DnsCheckResponse;
import com.example.dnsautomation.service.DnsCheckFacade;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Arrays;
import java.util.List;

@Controller
public class WebController {

    private final DnsCheckFacade dnsCheckFacade;

    public WebController(DnsCheckFacade dnsCheckFacade) {
        this.dnsCheckFacade = dnsCheckFacade;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/check")
    public String check(
            @RequestParam String domain,
            @RequestParam String publicIps,
            @RequestParam String selector,
            Model model) {

        List<String> ipList = Arrays.stream(publicIps.split("[,\\s]+"))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();

        DnsCheckRequest request = new DnsCheckRequest(domain.trim(), ipList, selector.trim());
        DnsCheckResponse response = dnsCheckFacade.check(request);

        model.addAttribute("response", response);
        return "result";
    }
}
