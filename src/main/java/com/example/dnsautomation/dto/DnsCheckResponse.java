package com.example.dnsautomation.dto;

import java.util.List;

public record DnsCheckResponse(
        String domain,
        SpfResult spf,
        DkimResult dkim,
        DmarcResult dmarc,
        List<PtrResult> ptrResults,
        String guideMarkdown
) {
    public boolean hasNotFoundPtr() {
        return ptrResults != null && ptrResults.stream()
                .anyMatch(p -> p.status() == PtrResult.PtrStatus.NOT_FOUND);
    }
}
