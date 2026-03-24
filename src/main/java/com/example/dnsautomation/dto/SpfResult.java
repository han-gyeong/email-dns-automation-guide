package com.example.dnsautomation.dto;

import java.util.List;

public record SpfResult(
        SpfStatus status,
        String currentRecord,
        String recommendedRecord,
        List<String> addedIps,
        String errorMessage
) {
    public enum SpfStatus {
        NEW, MODIFIED, UNCHANGED, CONFLICT_ERROR
    }

    public static SpfResult newRecord(String recommendedRecord, List<String> ips) {
        return new SpfResult(SpfStatus.NEW, null, recommendedRecord, ips, null);
    }

    public static SpfResult modified(String current, String recommended, List<String> addedIps) {
        return new SpfResult(SpfStatus.MODIFIED, current, recommended, addedIps, null);
    }

    public static SpfResult unchanged(String current) {
        return new SpfResult(SpfStatus.UNCHANGED, current, current, List.of(), null);
    }

    public static SpfResult conflict(String errorMessage) {
        return new SpfResult(SpfStatus.CONFLICT_ERROR, null, null, List.of(), errorMessage);
    }

    /**
     * AS-IS 표시용 — 레코드가 길면 앞부분 + [중략] + all 정책만 남겨 요약
     */
    public String currentRecordAbbreviated() {
        if (currentRecord == null) return null;
        if (currentRecord.length() <= 80) return currentRecord;
        String allPolicy = "";
        if (currentRecord.contains(" ~all")) allPolicy = " ~all";
        else if (currentRecord.contains(" -all")) allPolicy = " -all";
        else if (currentRecord.contains(" +all")) allPolicy = " +all";
        return currentRecord.substring(0, 55) + " [중략]" + allPolicy;
    }

    /**
     * 이메일 템플릿 전용 TO-BE:
     * - 기존 IP 부분은 [중략] 처리
     * - 추가된 IP만 <strong> 볼드로 표시
     * - 신규(기존 없음) 케이스는 전체 볼드
     */
    public String recommendedRecordForEmail() {
        if (recommendedRecord == null) return null;

        // 추가 IP 없음(UNCHANGED) → 기존 축약본 그대로
        if (addedIps == null || addedIps.isEmpty()) {
            return currentRecordAbbreviated() != null ? currentRecordAbbreviated() : recommendedRecord;
        }

        // 신규(기존 레코드 없음) → 전체 볼드, 축약 없음
        if (currentRecord == null) {
            return "<strong style=\"color:#3182F6\">" + recommendedRecord + "</strong>";
        }

        // 기존 있음 + 추가 IP 있음 → 기존 부분 [중략] + 추가 IP 볼드
        String abbreviated = currentRecordAbbreviated();
        String allPolicy = "";
        String base = abbreviated;
        if (abbreviated.endsWith(" ~all")) { allPolicy = " ~all"; base = abbreviated.substring(0, abbreviated.length() - 5); }
        else if (abbreviated.endsWith(" -all")) { allPolicy = " -all"; base = abbreviated.substring(0, abbreviated.length() - 5); }
        else if (abbreviated.endsWith(" +all")) { allPolicy = " +all"; base = abbreviated.substring(0, abbreviated.length() - 5); }

        String boldIps = addedIps.stream()
                .map(ip -> "<strong style=\"color:#3182F6\">ip4:" + ip + "</strong>")
                .collect(java.util.stream.Collectors.joining(" "));

        return base + " " + boldIps + allPolicy;
    }

    /**
     * TO-BE 값에서 추가된 IP를 <strong> 태그로 감싼 HTML 문자열 반환
     * th:utext로 렌더링 시 사용
     */
    public String recommendedRecordHighlighted() {
        if (recommendedRecord == null) return null;
        if (addedIps == null || addedIps.isEmpty()) return recommendedRecord;
        String result = recommendedRecord;
        for (String ip : addedIps) {
            result = result.replace(
                "ip4:" + ip,
                "<strong style=\"color:var(--color-primary)\">ip4:" + ip + "</strong>"
            );
        }
        return result;
    }
}
