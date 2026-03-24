package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.DmarcResult;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DmarcService {

    public DmarcResult generate(String domain, List<String> existingDmarcRecords) {
        List<String> dmarcRecords = existingDmarcRecords.stream()
                .filter(r -> r.startsWith("v=DMARC1"))
                .toList();

        if (!dmarcRecords.isEmpty()) {
            return DmarcResult.existing(dmarcRecords.get(0));
        }

        String recommended = "v=DMARC1; p=none; rua=mailto:admin@" + domain;
        return DmarcResult.newRecord(recommended);
    }
}
