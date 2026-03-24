package com.example.dnsautomation.dto;

public record PtrResult(
        String ip,
        String ptrRecord,
        PtrStatus status
) {
    public enum PtrStatus {
        EXISTS, NOT_FOUND
    }

    public static PtrResult found(String ip, String ptrRecord) {
        return new PtrResult(ip, ptrRecord, PtrStatus.EXISTS);
    }

    public static PtrResult notFound(String ip) {
        return new PtrResult(ip, null, PtrStatus.NOT_FOUND);
    }
}
