package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.DkimResult;
import com.example.dnsautomation.dto.DmarcResult;
import com.example.dnsautomation.dto.DnsCheckRequest;
import com.example.dnsautomation.dto.DnsCheckResponse;
import com.example.dnsautomation.dto.PtrResult;
import com.example.dnsautomation.dto.SpfResult;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class DnsCheckFacade {

    private final DnsQueryService dnsQueryService;
    private final SpfService spfService;
    private final DkimService dkimService;
    private final DmarcService dmarcService;
    private final GuideGeneratorService guideGeneratorService;

    public DnsCheckFacade(DnsQueryService dnsQueryService, SpfService spfService,
                          DkimService dkimService, DmarcService dmarcService,
                          GuideGeneratorService guideGeneratorService) {
        this.dnsQueryService = dnsQueryService;
        this.spfService = spfService;
        this.dkimService = dkimService;
        this.dmarcService = dmarcService;
        this.guideGeneratorService = guideGeneratorService;
    }

    public DnsCheckResponse check(DnsCheckRequest request) {
        String domain = request.domain();
        String selector = request.selector();
        List<String> publicIps = request.publicIps();

        Map<String, List<String>> txtRecords = dnsQueryService.queryTxt(domain, selector);
        List<PtrResult> ptrResults = dnsQueryService.queryPtr(publicIps);

        List<String> domainTxtRecords = txtRecords.getOrDefault(domain, List.of());
        List<String> dkimTxtRecords = txtRecords.getOrDefault(selector + "._domainkey." + domain, List.of());
        List<String> dmarcTxtRecords = txtRecords.getOrDefault("_dmarc." + domain, List.of());

        SpfResult spf = spfService.analyze(domainTxtRecords, publicIps);
        DkimResult dkim = dkimService.generate(selector, domain, dkimTxtRecords);
        DmarcResult dmarc = dmarcService.generate(domain, dmarcTxtRecords);
        String guideMarkdown = guideGeneratorService.generateMarkdown(domain, spf, dkim, dmarc, ptrResults);

        return new DnsCheckResponse(domain, spf, dkim, dmarc, ptrResults, guideMarkdown);
    }
}
