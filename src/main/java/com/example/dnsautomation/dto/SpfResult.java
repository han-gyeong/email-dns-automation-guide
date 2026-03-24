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
    /**
     * AS-IS 표시용 — 짧으면 그대로, 길면 v=spf1 [중략] ~all
     */
    public String currentRecordAbbreviated() {
        if (currentRecord == null) return null;
        if (currentRecord.length() <= 80) return currentRecord;
        return "v=spf1 [중략]" + extractAllPolicy(currentRecord);
    }

    /**
     * 이메일 템플릿 전용 TO-BE:
     * - 신규(기존 없음): 전체 볼드, 축약 없음
     * - 기존 있음 + 추가 IP: v=spf1 [중략] ip4:NEW1 ip4:NEW2 ~all (추가분 볼드)
     * - 변경 없음: currentRecordAbbreviated() 그대로
     */
    public String recommendedRecordForEmail() {
        if (recommendedRecord == null) return null;

        if (addedIps == null || addedIps.isEmpty()) {
            return currentRecordAbbreviated() != null ? currentRecordAbbreviated() : recommendedRecord;
        }

        if (currentRecord == null) {
            return "<strong style=\"color:#3182F6\">" + recommendedRecord + "</strong>";
        }

        String boldIps = addedIps.stream()
                .map(ip -> "<strong style=\"color:#3182F6\">ip4:" + ip + "</strong>")
                .collect(java.util.stream.Collectors.joining(" "));

        return "v=spf1 [중략] " + boldIps + extractAllPolicy(recommendedRecord);
    }

    private String extractAllPolicy(String record) {
        if (record.contains(" ~all")) return " ~all";
        if (record.contains(" -all")) return " -all";
        if (record.contains(" +all")) return " +all";
        return "";
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
