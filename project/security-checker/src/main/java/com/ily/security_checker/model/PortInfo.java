package com.ily.security_checker.model;

import java.util.List;

public record PortInfo(
    int port,
    String protocol,
    String state,
    String serviceName,
    String product,
    String version,
    String extrainfo,
    String cpe,
    List<String> allCpes
) {}
