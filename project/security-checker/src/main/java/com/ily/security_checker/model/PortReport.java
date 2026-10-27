package com.ily.security_checker.model;

import java.util.List;

public record PortReport(
    PortInfo portInfo,
    List<VulnerabilityIssue> vulnerabilities,
    String lookupError
) {}
