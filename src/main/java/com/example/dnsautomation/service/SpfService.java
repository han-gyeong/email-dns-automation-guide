package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.SpfResult;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SpfService {

    // RFC 7208 — DNS 조회 최대 10회
    private static final int MAX_INCLUDE_DEPTH = 10;

    private final DnsQueryService dnsQueryService;

    public SpfService(DnsQueryService dnsQueryService) {
        this.dnsQueryService = dnsQueryService;
    }

    public SpfResult analyze(List<String> txtRecords, List<String> publicIps) {
        List<String> spfRecords = txtRecords.stream()
                .filter(r -> r.startsWith("v=spf1"))
                .toList();

        if (spfRecords.size() > 1) {
            return SpfResult.conflict(
                    "SPF 레코드가 " + spfRecords.size() + "개 존재합니다. RFC 5321 위반 — 레코드를 하나로 통합해야 합니다."
            );
        }

        if (spfRecords.isEmpty()) {
            return buildNewRecord(publicIps);
        }

        return appendMissingIps(spfRecords.get(0), publicIps);
    }

    private SpfResult buildNewRecord(List<String> publicIps) {
        String ipPart = publicIps.stream()
                .map(ip -> "ip4:" + ip)
                .collect(Collectors.joining(" "));
        String recommended = "v=spf1 " + ipPart + " ~all";
        return SpfResult.newRecord(recommended, publicIps);
    }

    private SpfResult appendMissingIps(String existing, List<String> requestedIps) {
        // include: 재귀 조회로 커버되는 모든 IP/CIDR 수집
        Set<String> includeCoveredCidrs = resolveIncludedCidrs(existing, new HashSet<>());

        List<String> missingIps = requestedIps.stream()
                .filter(ip -> !isIpInRecord(ip, existing) && !isIpCoveredBySet(ip, includeCoveredCidrs))
                .toList();

        if (missingIps.isEmpty()) {
            return SpfResult.unchanged(existing);
        }

        String additions = missingIps.stream()
                .map(ip -> "ip4:" + ip)
                .collect(Collectors.joining(" "));

        // 마지막 ip4: 토큰 바로 뒤에 삽입 (include: 앞)
        // 예) v=spf1 ip4:A ip4:B include:X ~all → v=spf1 ip4:A ip4:B ip4:NEW include:X ~all
        String recommended = insertAfterLastIp4(existing, additions);
        if (recommended == null) {
            // ip4: 토큰이 없으면 all 정책 앞에 삽입
            if (existing.contains(" ~all")) {
                recommended = existing.replace(" ~all", " " + additions + " ~all");
            } else if (existing.contains(" -all")) {
                recommended = existing.replace(" -all", " " + additions + " -all");
            } else if (existing.contains(" +all")) {
                recommended = existing.replace(" +all", " " + additions + " +all");
            } else {
                recommended = existing + " " + additions;
            }
        }

        return SpfResult.modified(existing, recommended, missingIps);
    }

    /**
     * 기존 SPF 레코드에서 마지막 ip4: 토큰 바로 뒤에 additions를 삽입.
     * ip4: 토큰이 없으면 null 반환 (호출부에서 fallback 처리).
     */
    private String insertAfterLastIp4(String existing, String additions) {
        String[] tokens = existing.split("\\s+");
        int lastIp4Index = -1;
        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].startsWith("ip4:")) {
                lastIp4Index = i;
            }
        }
        if (lastIp4Index < 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < tokens.length; i++) {
            sb.append(tokens[i]);
            if (i == lastIp4Index) {
                sb.append(" ").append(additions);
            }
            if (i < tokens.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * SPF 레코드의 include: 지시어를 재귀적으로 따라가며 모든 ip4: CIDR을 수집
     * visitedDomains로 순환 참조 방지
     */
    private Set<String> resolveIncludedCidrs(String spfRecord, Set<String> visitedDomains) {
        Set<String> cidrs = new HashSet<>();
        if (visitedDomains.size() >= MAX_INCLUDE_DEPTH) {
            return cidrs;
        }

        for (String token : spfRecord.split("\\s+")) {
            if (token.startsWith("include:")) {
                String includeDomain = token.substring(8);
                if (visitedDomains.add(includeDomain)) { // 이미 방문한 도메인은 스킵
                    dnsQueryService.lookupTxtRecords(includeDomain).stream()
                            .filter(r -> r.startsWith("v=spf1"))
                            .findFirst()
                            .ifPresent(includeSpf -> cidrs.addAll(resolveIncludedCidrs(includeSpf, visitedDomains)));
                }
            }
            // include 도메인 자체의 ip4: 도 수집
            if (token.startsWith("ip4:")) {
                cidrs.add(token.substring(4));
            }
        }
        return cidrs;
    }

    /**
     * IP가 SPF 레코드의 ip4: 지시어에 직접 포함되는지 확인 (CIDR 포함)
     */
    private boolean isIpInRecord(String ip, String spfRecord) {
        return Arrays.stream(spfRecord.split("\\s+"))
                .filter(t -> t.startsWith("ip4:"))
                .map(t -> t.substring(4))
                .anyMatch(cidr -> ipMatchesCidr(ip, cidr));
    }

    /**
     * IP가 수집된 CIDR 집합 중 하나에 포함되는지 확인
     */
    private boolean isIpCoveredBySet(String ip, Set<String> cidrs) {
        return cidrs.stream().anyMatch(cidr -> ipMatchesCidr(ip, cidr));
    }

    /**
     * IPv4 CIDR 매칭
     * - "1.2.3.4"     → 정확히 일치하는 경우만
     * - "1.2.3.0/24"  → 네트워크 마스크 범위 내 포함 여부
     */
    private boolean ipMatchesCidr(String ip, String cidr) {
        try {
            if (!cidr.contains("/")) {
                return ip.equals(cidr);
            }
            String[] parts = cidr.split("/");
            int prefix = Integer.parseInt(parts[1]);
            long ipLong = ipToLong(ip);
            long networkLong = ipToLong(parts[0]);
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (ipLong & mask) == (networkLong & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        long result = 0;
        for (String octet : octets) {
            result = result * 256 + Long.parseLong(octet.trim());
        }
        return result;
    }
}
