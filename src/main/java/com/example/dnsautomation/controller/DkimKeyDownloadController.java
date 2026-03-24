package com.example.dnsautomation.controller;

import com.example.dnsautomation.service.DkimService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;

@RestController
@RequestMapping("/api/dns/dkim")
public class DkimKeyDownloadController {

    private static final Logger log = LoggerFactory.getLogger(DkimKeyDownloadController.class);

    private final DkimService dkimService;

    public DkimKeyDownloadController(DkimService dkimService) {
        this.dkimService = dkimService;
    }

    @GetMapping("/private-key/{selector}/{domain}")
    public ResponseEntity<Resource> downloadPrivateKey(
            @PathVariable String selector,
            @PathVariable String domain) {
        try {
            Path filePath = dkimService.resolveLatestKeyFile(selector, domain);

            if (filePath == null) {
                return ResponseEntity.notFound().build();
            }

            // Path Traversal 방지: 저장 경로 하위인지 검증
            Path storagePath = dkimService.getStoragePath();
            if (!filePath.toAbsolutePath().normalize().startsWith(storagePath)) {
                log.warn("Path traversal 시도 감지. selector={}, domain={}", selector, domain);
                return ResponseEntity.badRequest().build();
            }

            String fileName = filePath.getFileName().toString();
            Resource resource = new FileSystemResource(filePath);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (Exception e) {
            log.error("DKIM Private Key 다운로드 실패. selector={}, domain={}", selector, domain, e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
