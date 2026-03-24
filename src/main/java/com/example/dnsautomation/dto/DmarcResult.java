package com.example.dnsautomation.dto;

public record DmarcResult(
        DmarcStatus status,
        String currentRecord,
        String recommendedRecord
) {
    public enum DmarcStatus {
        NEW, EXISTING
    }

    public static DmarcResult newRecord(String recommendedRecord) {
        return new DmarcResult(DmarcStatus.NEW, null, recommendedRecord);
    }

    public static DmarcResult existing(String currentRecord) {
        return new DmarcResult(DmarcStatus.EXISTING, currentRecord, currentRecord);
    }
}
