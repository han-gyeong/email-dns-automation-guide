package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.DkimResult;
import com.example.dnsautomation.dto.DmarcResult;
import com.example.dnsautomation.dto.PtrResult;
import com.example.dnsautomation.dto.SpfResult;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GuideGeneratorService {

    public String generateMarkdown(String domain, SpfResult spf, DkimResult dkim,
                                    DmarcResult dmarc, List<PtrResult> ptrResults) {
        StringBuilder sb = new StringBuilder();
        sb.append("# DNS 설정 가이드 — ").append(domain).append("\n\n");
        sb.append("---\n\n");

        appendSpfSection(sb, domain, spf);
        appendDkimSection(sb, dkim);
        appendDmarcSection(sb, domain, dmarc);
        appendPtrSection(sb, ptrResults);

        return sb.toString();
    }

    private void appendSpfSection(StringBuilder sb, String domain, SpfResult spf) {
        sb.append("## 1. SPF 레코드");
        switch (spf.status()) {
            case NEW -> sb.append(" (신규 생성 필요)\n");
            case MODIFIED -> sb.append(" (수정 필요)\n");
            case UNCHANGED -> sb.append(" (변경 없음)\n");
            case CONFLICT_ERROR -> sb.append(" (⚠️ 충돌 오류)\n");
        }
        sb.append("\n");
        sb.append("| 항목 | 값 |\n");
        sb.append("|------|----|\n");
        sb.append("| 레코드 타입 | TXT |\n");
        sb.append("| 호스트 | ").append(domain).append(" |\n");
        if (spf.currentRecord() != null) {
            sb.append("| 현재값 | `").append(spf.currentRecord()).append("` |\n");
        }
        if (spf.status() == SpfResult.SpfStatus.CONFLICT_ERROR) {
            sb.append("\n> ⚠️ **오류**: ").append(spf.errorMessage()).append("\n");
        } else if (spf.recommendedRecord() != null) {
            sb.append("| **적용값** | `").append(spf.recommendedRecord()).append("` |\n");
        }
        sb.append("\n");
    }

    private void appendDkimSection(StringBuilder sb, DkimResult dkim) {
        boolean isExisting = dkim.status() == DkimResult.DkimStatus.EXISTING;
        sb.append("## 2. DKIM 레코드").append(isExisting ? " (기존 레코드 유지)\n\n" : " (신규)\n\n");
        sb.append("| 항목 | 값 |\n");
        sb.append("|------|----|\n");
        sb.append("| 레코드 타입 | TXT |\n");
        sb.append("| 호스트 | `").append(dkim.dnsName()).append("` |\n");
        sb.append("| **적용값** | `").append(dkim.dnsValue()).append("` |\n");
        if (!isExisting && dkim.privateKeyFileName() != null) {
            sb.append("| Private Key | [").append(dkim.privateKeyFileName()).append("](")
                    .append(dkim.privateKeyDownloadUrl()).append(") |\n");
        }
        if (isExisting) {
            sb.append("\n> ℹ️ 기존 DKIM 레코드가 있어 그대로 유지합니다.\n");
        }
        sb.append("\n");
    }

    private void appendDmarcSection(StringBuilder sb, String domain, DmarcResult dmarc) {
        sb.append("## 3. DMARC 레코드");
        if (dmarc.status() == DmarcResult.DmarcStatus.EXISTING) {
            sb.append(" (기존 레코드 유지)\n\n");
            sb.append("| 항목 | 값 |\n");
            sb.append("|------|----|\n");
            sb.append("| 레코드 타입 | TXT |\n");
            sb.append("| 호스트 | `_dmarc.").append(domain).append("` |\n");
            sb.append("| 현재값 | `").append(dmarc.currentRecord()).append("` |\n");
            sb.append("\n> ℹ️ 기존 DMARC 레코드가 있어 그대로 유지합니다.\n");
        } else {
            sb.append(" (신규 생성 필요)\n\n");
            sb.append("| 항목 | 값 |\n");
            sb.append("|------|----|\n");
            sb.append("| 레코드 타입 | TXT |\n");
            sb.append("| 호스트 | `_dmarc.").append(domain).append("` |\n");
            sb.append("| **적용값** | `").append(dmarc.recommendedRecord()).append("` |\n");
        }
        sb.append("\n");
    }

    private void appendPtrSection(StringBuilder sb, List<PtrResult> ptrResults) {
        sb.append("## 4. PTR 레코드 (역방향 DNS) 조회 결과\n\n");
        sb.append("| IP 주소 | PTR 레코드 | 상태 |\n");
        sb.append("|---------|-----------|------|\n");
        for (PtrResult ptr : ptrResults) {
            String ptrValue = ptr.ptrRecord() != null ? "`" + ptr.ptrRecord() + "`" : "-";
            String statusLabel = ptr.status() == PtrResult.PtrStatus.EXISTS ? "✅ 존재" : "❌ 미설정";
            sb.append("| ").append(ptr.ip()).append(" | ").append(ptrValue)
                    .append(" | ").append(statusLabel).append(" |\n");
        }

        boolean hasNotFound = ptrResults.stream()
                .anyMatch(p -> p.status() == PtrResult.PtrStatus.NOT_FOUND);
        if (hasNotFound) {
            sb.append("\n> ⚠️ **역방향 DNS 미설정 IP가 있습니다.** ")
                    .append("PTR 레코드가 없으면 수신 서버에서 스팸으로 분류될 수 있습니다. ")
                    .append("ISP 또는 호스팅 업체에 PTR 레코드 등록을 요청하세요.\n");
        }
    }
}
