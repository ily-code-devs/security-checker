package com.ily.security_checker.service;

import com.ily.security_checker.VulnerabilityLookupClient;
import com.ily.security_checker.model.PortInfo;
import com.ily.security_checker.model.ScanResult;
import com.ily.security_checker.model.SecurityReport;
import com.ily.security_checker.model.VulnerabilityIssue;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecurityReportServiceTest {

    @Test
    void combinesPortScanAndVulnerabilityLookupWithSeverityCounts() {
        PortScannerService scanner = mock(PortScannerService.class);
        VulnerabilityLookupClient vulnClient = mock(VulnerabilityLookupClient.class);

        String redisCpe = "cpe:/a:redislabs:redis:6.2.17";
        PortInfo port6379 = new PortInfo(
                6379, "tcp", "open", "redis", "Redis key-value store", "6.2.17", "", redisCpe, List.of(redisCpe)
        );
        ScanResult scanResult = new ScanResult(
                "127.0.0.1", "up", Instant.parse("2026-10-27T12:00:00Z"), List.of(port6379), "Found 1 open ports"
        );

        VulnerabilityIssue critIssue = new VulnerabilityIssue(
                "CVE-2025-0001", redisCpe, "Critical Redis Issue", "Desc 1", "CRITICAL", 9.8,
                Instant.parse("2025-01-01T00:00:00Z"), Instant.parse("2025-01-02T00:00:00Z"),
                List.of("https://example.com/cve1"), List.of("CWE-119")
        );
        VulnerabilityIssue highIssue = new VulnerabilityIssue(
                "CVE-2025-0002", redisCpe, "High Redis Issue", "Desc 2", "HIGH", 7.5,
                Instant.parse("2025-02-01T00:00:00Z"), Instant.parse("2025-02-02T00:00:00Z"),
                List.of("https://example.com/cve2"), List.of("CWE-20")
        );

        when(scanner.scan("127.0.0.1", "6379")).thenReturn(scanResult);
        when(vulnClient.GetVulnFromCPE(redisCpe)).thenReturn(List.of(critIssue, highIssue));

        SecurityReportService service = new SecurityReportService(scanner, vulnClient);
        SecurityReport report = service.runFullScan("127.0.0.1", "6379");

        assertNotNull(report);
        assertEquals("127.0.0.1", report.target());
        assertEquals("up", report.hostStatus());
        assertEquals(1, report.totalOpenPorts());
        assertEquals(2, report.totalVulnerabilities());
        assertEquals(1, report.criticalCount());
        assertEquals(1, report.highCount());
        assertEquals(0, report.mediumCount());
        assertEquals(0, report.lowCount());
        verify(vulnClient, times(1)).GetVulnFromCPE(redisCpe);
    }
}
