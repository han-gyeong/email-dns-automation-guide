package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.PtrResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class DnsQueryService {

    private static final Logger log = LoggerFactory.getLogger(DnsQueryService.class);

    /**
     * domain TXT, selector._domainkey.domain TXT, _dmarc.domain TXT 조회
     *
     * @return 조회 대상별 TXT 레코드 값 목록 (키: 조회 호스트명)
     */
    public Map<String, List<String>> queryTxt(String domain, String selector) {
        Map<String, List<String>> result = new HashMap<>();
        result.put(domain, lookupTxt(domain));
        result.put(selector + "._domainkey." + domain, lookupTxt(selector + "._domainkey." + domain));
        result.put("_dmarc." + domain, lookupTxt("_dmarc." + domain));
        return result;
    }

    /**
     * 각 publicIp에 대해 PTR 레코드 조회
     */
    public List<PtrResult> queryPtr(List<String> publicIps) {
        List<PtrResult> results = new ArrayList<>();
        for (String ip : publicIps) {
            results.add(lookupPtr(ip));
        }
        return results;
    }

    /**
     * 단일 호스트명 TXT 레코드 조회 (SpfService의 include 재귀 조회용으로 공개)
     */
    public List<String> lookupTxtRecords(String hostname) {
        return lookupTxt(hostname);
    }

    private List<String> lookupTxt(String hostname) {
        try {
            Lookup lookup = new Lookup(hostname, Type.TXT);
            Record[] records = lookup.run();
            if (records == null) {
                return List.of();
            }
            List<String> values = new ArrayList<>();
            for (Record record : records) {
                TXTRecord txt = (TXTRecord) record;
                values.add(String.join("", txt.getStrings()));
            }
            return values;
        } catch (Exception e) {
            log.warn("TXT 조회 실패. hostname={}, error={}", hostname, e.getMessage());
            return List.of();
        }
    }

    private PtrResult lookupPtr(String ip) {
        String reversedIp = buildReverseIp(ip);
        String ptrHostname = reversedIp + ".in-addr.arpa.";
        try {
            Lookup lookup = new Lookup(ptrHostname, Type.PTR);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                return PtrResult.notFound(ip);
            }
            PTRRecord ptr = (PTRRecord) records[0];
            String ptrValue = ptr.getTarget().toString();
            return PtrResult.found(ip, ptrValue);
        } catch (Exception e) {
            log.warn("PTR 조회 실패. ip={}, error={}", ip, e.getMessage());
            return PtrResult.notFound(ip);
        }
    }

    /**
     * "1.2.3.4" → "4.3.2.1"
     */
    private String buildReverseIp(String ip) {
        String[] octets = ip.split("\\.");
        return octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0];
    }
}
