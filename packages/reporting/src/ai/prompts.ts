// ── AI Prompt Templates ─────────────────────────────────────────────────────
// All prompts instruct the AI to analyze ONLY provided artifacts.
// The AI must NEVER attempt to execute, download, or interact with samples.

/**
 * Shared system instructions included in every AI analysis call.
 * Enforces the safety boundary: AI operates only on pre-analyzed artifacts.
 */
export const SYSTEM_INSTRUCTIONS = `You are a senior malware analyst assistant for the FraudVault enterprise malware analysis platform. You analyze ONLY the pre-processed analysis artifacts provided to you.

CRITICAL SAFETY RULES:
- You must ONLY analyze the provided artifacts (analysis results, IOCs, metadata). You do NOT have access to the actual malware sample.
- NEVER attempt to execute, download, reconstruct, or interact with any sample or payload.
- NEVER generate executable code, shellcode, or exploit code based on the analysis.
- If the provided data is insufficient for a confident assessment, clearly state your confidence level and what additional analysis would be needed.

ANALYSIS GUIDELINES:
- Be precise and reference specific indicators from the provided data (hashes, IPs, domains, technique IDs, etc.).
- Use appropriate cybersecurity terminology (MITRE ATT&CK, kill chain phases, threat actor nomenclature).
- Clearly state your confidence level (high, medium, low) for each significant finding.
- Flag anything that warrants further manual investigation by a human analyst.
- When referencing MITRE ATT&CK techniques, use the standard TID format (e.g., T1055).
- Distinguish between confirmed indicators and inferred/circumstantial evidence.`;

/**
 * Summarize dynamic analysis behaviors for a SOC analyst.
 * Input: Dynamic analysis results (processes, network, file/registry changes, behavior tags).
 */
export const BEHAVIOR_SUMMARY_PROMPT = `Analyze the following dynamic analysis results from a sandboxed malware detonation and provide a behavior summary for a SOC analyst.

Summarize the observed behaviors in 2-3 focused paragraphs covering:
1. Process execution chain and any suspicious process relationships (parent-child, injection, etc.)
2. Network activity including C2 communication patterns, data exfiltration indicators, and DNS queries
3. Persistence mechanisms and system modifications (file drops, registry changes, mutexes)

Highlight the most concerning behaviors and explain WHY they are suspicious. Reference specific IOCs and behavior tags from the data.

DYNAMIC ANALYSIS RESULTS:
{{DATA}}`;

/**
 * Generate a non-technical executive summary.
 * Input: Full analysis report (sanitized).
 */
export const EXECUTIVE_SUMMARY_PROMPT = `Generate a concise, non-technical executive summary (1 paragraph, 4-6 sentences) of the following malware analysis report. This summary is intended for executives and non-technical stakeholders.

The summary should:
- State whether the file is malicious and the overall risk level in plain language
- Describe the potential business impact without using technical jargon
- Mention the number of systems or data types that could be affected
- Include a clear, actionable recommendation (e.g., "block immediately", "monitor closely", "no action needed")
- Avoid acronyms, technical indicators, and security-specific terminology where possible

ANALYSIS REPORT:
{{DATA}}`;

/**
 * Detailed technical analysis for malware researchers.
 * Input: Full analysis report (sanitized).
 */
export const TECHNICAL_ANALYSIS_PROMPT = `Provide a detailed technical analysis of the following malware analysis results, written for experienced malware researchers and reverse engineers.

Structure your analysis as follows:
1. **Sample Overview**: File characteristics, packing/obfuscation, and initial classification
2. **Static Analysis Findings**: Notable imports, sections, strings, entropy analysis, and certificate status
3. **Dynamic Behavior Analysis**: Execution flow, process tree, injection techniques, evasion mechanisms
4. **Network Infrastructure**: C2 communication protocols, domains, IPs, and traffic patterns
5. **Persistence & Impact**: Persistence mechanisms, data access, lateral movement capabilities
6. **MITRE ATT&CK Mapping**: Detailed mapping of observed behaviors to ATT&CK techniques with confidence levels
7. **Threat Attribution**: Any indicators suggesting threat actor or malware family attribution (with confidence)
8. **Gaps & Recommendations**: What the automated analysis may have missed; recommended follow-up analysis

Reference specific indicators (hashes, IPs, domains, registry keys, mutexes, technique IDs) throughout.

ANALYSIS REPORT:
{{DATA}}`;

/**
 * Threat assessment with containment/remediation recommendations.
 * Input: Full analysis report (sanitized).
 */
export const THREAT_ASSESSMENT_PROMPT = `Based on the following malware analysis report, provide a structured threat assessment.

Respond in the following JSON format (and ONLY this JSON, no markdown fencing):
{
  "summary": "2-3 sentence threat summary",
  "riskLevel": "critical|high|medium|low|informational",
  "recommendations": [
    "Specific, actionable recommendation 1",
    "Specific, actionable recommendation 2"
  ]
}

Your assessment should consider:
- Severity and sophistication of observed behaviors
- Network indicators and potential for lateral movement or data exfiltration
- Known threat intelligence associations (malware family, threat actor)
- Persistence mechanisms and difficulty of remediation
- Potential blast radius within an enterprise environment

Recommendations should be prioritized (most urgent first) and specific enough for a SOC team to act on immediately.

ANALYSIS REPORT:
{{DATA}}`;

/**
 * Explain the significance of extracted IOCs.
 * Input: Array of IOC objects.
 */
export const IOC_CONTEXT_PROMPT = `Analyze the following Indicators of Compromise (IOCs) extracted from a malware analysis and explain their significance.

For each notable IOC or group of related IOCs, explain:
1. What the indicator likely represents (C2 server, drop zone, exfiltration endpoint, etc.)
2. The confidence level of the indicator (high/medium/low) and why
3. How it relates to other IOCs in the set (e.g., domain resolving to IP, URL path patterns)
4. Recommended detection/blocking actions specific to each indicator type
5. Any patterns suggesting infrastructure reuse, DGA, fast-flux, or bulletproof hosting

Group related IOCs together rather than analyzing each in isolation. Highlight the highest-priority IOCs for immediate blocking.

EXTRACTED IOCs:
{{DATA}}`;

/**
 * Describe the kill chain / attack flow based on ATT&CK mappings.
 * Input: Array of ATT&CK technique objects.
 */
export const ATTACK_CHAIN_PROMPT = `Based on the following MITRE ATT&CK technique mappings observed during malware analysis, reconstruct and describe the likely attack chain (kill chain).

For your analysis:
1. Organize the techniques by kill chain phase (Initial Access -> Execution -> Persistence -> Privilege Escalation -> Defense Evasion -> Credential Access -> Discovery -> Lateral Movement -> Collection -> Exfiltration -> Command and Control -> Impact)
2. For each phase where techniques were observed, describe what the malware is doing and WHY
3. Identify gaps in the kill chain that suggest capabilities not observed (possibly due to sandbox limitations or conditional triggers)
4. Assess the overall sophistication level (commodity malware, moderate, advanced/APT)
5. Note any technique combinations that are characteristic of known threat actors or malware families
6. Provide confidence levels for the kill chain reconstruction

Present the attack flow as a narrative, not just a list. Explain how each phase connects to the next.

OBSERVED ATT&CK TECHNIQUES:
{{DATA}}`;
