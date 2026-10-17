package com.ily.security_checker;

import com.ily.security_checker.model.VulnerabilityIssue;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.List;

@SpringBootApplication
public class SecurityCheckerApplication {

	public static void main(String[] args) {
		ConfigurableApplicationContext context = SpringApplication.run(SecurityCheckerApplication.class, args);

		VulnerabilityLookupClient client = context.getBean(VulnerabilityLookupClient.class);
		List<VulnerabilityIssue> issues = client.GetVulnFromCPE(
				"cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*");

		System.out.println("Found " + issues.size() + " vulnerability issue(s):");
		for (VulnerabilityIssue issue : issues) {
			System.out.println(issue.name());
		}
	}

}
