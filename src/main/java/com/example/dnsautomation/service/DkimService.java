package com.example.dnsautomation.service;

import com.example.dnsautomation.dto.DkimResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;

@Service
public class DkimService {

    private static final Logger log = LoggerFactory.getLogger(DkimService.class);
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    @Value("${dkim.key-storage-path}")
    private String keyStoragePath;

    /**
     * 기존 DKIM 레코드가 있으면 기존 값 유지, 없으면 RSA 2048 키 신규 생성
     *
     * @param existingDkimRecords DNS에서 조회된 기존 DKIM 레코드 목록
     */
    public DkimResult generate(String selector, String domain, List<String> existingDkimRecords) {
        String dnsName = selector + "._domainkey." + domain;

        if (existingDkimRecords != null && !existingDkimRecords.isEmpty()) {
            log.info("기존 DKIM 레코드 존재 — 기존 값 유지. dnsName={}", dnsName);
            return DkimResult.existing(selector, dnsName, existingDkimRecords.get(0));
        }

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            String fileName = buildFileName(selector, domain);
            savePrivateKey(keyPair, fileName);

            String publicKeyBase64 = Base64.getEncoder()
                    .encodeToString(keyPair.getPublic().getEncoded());
            String dnsValue = "v=DKIM1; k=rsa; p=" + publicKeyBase64;
            String downloadUrl = "/api/dns/dkim/private-key/" + selector + "/" + domain;

            return DkimResult.newRecord(selector, dnsName, dnsValue, fileName, downloadUrl);

        } catch (Exception e) {
            log.error("DKIM 키 생성 실패. selector={}, domain={}", selector, domain, e);
            throw new RuntimeException("DKIM 키 생성 중 오류가 발생했습니다.", e);
        }
    }

    private String buildFileName(String selector, String domain) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        return selector + "_" + domain + "_" + timestamp + ".der";
    }

    private void savePrivateKey(KeyPair keyPair, String fileName) throws Exception {
        Path storagePath = Paths.get(keyStoragePath);
        Files.createDirectories(storagePath);
        Path filePath = storagePath.resolve(fileName);
        // getEncoded()는 PKCS#8 DER 바이너리를 반환 — 변환 없이 그대로 저장
        Files.write(filePath, keyPair.getPrivate().getEncoded());
        log.info("DKIM Private Key 저장 완료. path={}", filePath);
    }

    /**
     * 저장된 DER 파일 중 selector+domain에 해당하는 가장 최신 파일 경로 반환
     */
    public Path resolveLatestKeyFile(String selector, String domain) throws Exception {
        Path storagePath = Paths.get(keyStoragePath).toAbsolutePath().normalize();
        String prefix = selector + "_" + domain + "_";

        return Files.list(storagePath)
                .filter(p -> p.getFileName().toString().startsWith(prefix)
                        && p.getFileName().toString().endsWith(".der"))
                .max((a, b) -> a.getFileName().compareTo(b.getFileName()))
                .orElse(null);
    }

    public Path getStoragePath() {
        return Paths.get(keyStoragePath).toAbsolutePath().normalize();
    }
}
