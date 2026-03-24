package com.example.dnsautomation.dto;

public record DkimResult(
        DkimStatus status,
        String selector,
        String dnsName,
        String dnsValue,
        String existingDnsValue,
        String privateKeyFileName,
        String privateKeyDownloadUrl
) {
    public enum DkimStatus {
        NEW, EXISTING
    }

    public static DkimResult newRecord(String selector, String dnsName, String dnsValue,
                                       String fileName, String downloadUrl) {
        return new DkimResult(DkimStatus.NEW, selector, dnsName, dnsValue, null, fileName, downloadUrl);
    }

    public static DkimResult existing(String selector, String dnsName, String existingDnsValue) {
        return new DkimResult(DkimStatus.EXISTING, selector, dnsName, existingDnsValue, existingDnsValue, null, null);
    }

    public boolean hasExistingRecord() {
        return existingDnsValue != null && !existingDnsValue.isBlank();
    }

    /** AS-IS 표시용 — 공개키 부분을 [중략] 처리 */
    public String existingDnsValueAbbreviated() {
        return abbreviateDkimValue(existingDnsValue);
    }

    /** TO-BE 표시용 — 공개키 부분을 [중략] 처리 (이메일 본문 표시용) */
    public String dnsValueAbbreviated() {
        return abbreviateDkimValue(dnsValue);
    }

    private static String abbreviateDkimValue(String value) {
        if (value == null) return null;
        int pIdx = value.indexOf("p=");
        if (pIdx == -1 || value.length() - pIdx <= 30) return value;
        return value.substring(0, pIdx + 10) + "[중략]";
    }
}
