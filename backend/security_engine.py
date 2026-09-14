"""
IPsecGuard AI - Security Assessment Engine
Implements mathematically grounded scoring and rule-based evaluation based on:
- NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)
- RFC 4301 (Security Architecture for the Internet Protocol)
- RFC 7296 (Internet Key Exchange Protocol Version 2 - IKEv2)
- RFC 8221 (Cryptographic Algorithm Implementation Requirements for ESP and AH)
"""

from typing import Dict, Any, List

class SecurityAssessmentEngine:
    """
    Evaluates IPsec VPN configuration parameters against modern cryptographic
    standards and calculates an explainable security score (0-100), risk tier,
    categorized findings, and threat matrix.
    """

    @staticmethod
    def assess_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
        score = 100
        findings: List[Dict[str, str]] = []
        threats: List[Dict[str, str]] = []
        strengths: List[str] = []
        weaknesses: List[str] = []

        ike_version = str(config.get("ike_version", "IKEv2")).upper()
        mode = str(config.get("mode", "Tunnel")).capitalize()
        encryption = str(config.get("encryption", "AES-256")).upper()
        authentication = str(config.get("authentication", "HMAC-SHA256")).upper()
        dh_group = str(config.get("dh_group", "Group 14"))
        pfs = bool(config.get("pfs", True))
        replay_protection = bool(config.get("replay_protection", True))
        key_lifetime = int(config.get("key_lifetime", 28800))
        ip_version = str(config.get("ip_version", "IPv4")).upper()

        # 1. EVALUATE ENCRYPTION
        if "GCM" in encryption:
            strengths.append(f"{encryption} provides modern Authenticated Encryption with Associated Data (AEAD).")
            threats.append({
                "threat": "Ciphertext Tampering / Bit-flipping",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "Maintain AES-GCM; verify nonce uniqueness across rekeys."
            })
        elif "256" in encryption:
            strengths.append(f"{encryption} delivers robust 256-bit symmetric security margin.")
            threats.append({
                "threat": "Brute-force Key Recovery",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "Current key length is resistant to classical and quantum attacks."
            })
        elif "128" in encryption:
            score -= 8
            weaknesses.append("AES-128 offers adequate baseline security but lower safety margin than AES-256.")
            findings.append({
                "finding": "Sub-Optimal Encryption Key Length (AES-128)",
                "severity": "Low",
                "explanation": "AES-128 is theoretically secure today, but provides half the key-space depth of AES-256 against future computational breakthroughs.",
                "impact": "Reduced security lifespan against advanced cryptanalytic advances.",
                "recommendation": "Upgrade to AES-256 or AES-256-GCM for enterprise and government communications."
            })
            threats.append({
                "threat": "Long-term Cipher Exhaustion",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Medium",
                "status": "At Risk",
                "recommendation": "Migrate to AES-256."
            })
        elif "3DES" in encryption or "DES" in encryption:
            score -= 35
            weaknesses.append("3DES/DES is severely deprecated and subject to Sweet32 64-bit block collision attacks.")
            findings.append({
                "finding": "Deprecated Cipher Suite (3DES/DES)",
                "severity": "Critical",
                "explanation": "64-bit block ciphers are vulnerable to collision attacks (Sweet32, CVE-2016-2183) after capturing ~32GB of data under the same key.",
                "impact": "Potential recovery of plaintext HTTP cookies and sensitive session tokens.",
                "recommendation": "Immediately purge 3DES from proposals and mandate AES-GCM or AES-CBC."
            })
            threats.append({
                "threat": "Sweet32 Collision Attack (CVE-2016-2183)",
                "severity": "Critical",
                "likelihood": "High",
                "impact": "Critical",
                "status": "Vulnerable",
                "recommendation": "Cease using 64-bit block ciphers immediately."
            })

        if "CBC" in encryption:
            score -= 5
            weaknesses.append("CBC mode requires separate MAC and is susceptible to padding oracle side-channels if improperly validated.")
            findings.append({
                "finding": "Cipher Block Chaining (CBC) Mode in Use",
                "severity": "Low",
                "explanation": "AES-CBC requires Encrypt-then-MAC validation to prevent padding oracle attacks and bit-flipping tampering.",
                "impact": "If integrity check implementation fails or leaks timing, padding oracles may decrypt ciphertext blocks.",
                "recommendation": "Adopt AEAD ciphers like AES-GCM which combine confidentiality and authentication natively."
            })

        # 2. EVALUATE AUTHENTICATION / INTEGRITY
        if "SHA1" in authentication or "SHA-1" in authentication:
            score -= 18
            weaknesses.append("HMAC-SHA1 relies on a weakened hash function vulnerable to collision attacks (SHAttered).")
            findings.append({
                "finding": "Deprecated Integrity Algorithm (HMAC-SHA1)",
                "severity": "High",
                "explanation": "SHA-1 has proven collision vulnerabilities (SHAttered attack). While HMAC-SHA1 is marginally safer than raw SHA-1, NIST formally deprecated SHA-1 across all federal systems.",
                "impact": "Heightened risk of collision-based integrity bypasses in future protocol phases.",
                "recommendation": "Upgrade authentication algorithm to HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512."
            })
            threats.append({
                "threat": "Cryptographic Hash Collision (SHA-1)",
                "severity": "High",
                "likelihood": "Medium",
                "impact": "High",
                "status": "Vulnerable",
                "recommendation": "Replace HMAC-SHA1 with HMAC-SHA256 or SHA-512."
            })
        elif "MD5" in authentication:
            score -= 28
            weaknesses.append("HMAC-MD5 uses a thoroughly broken hash function.")
            findings.append({
                "finding": "Insecure Integrity Algorithm (MD5)",
                "severity": "Critical",
                "explanation": "MD5 suffers from rapid practical collision attacks and should never be used for security-critical protocols.",
                "impact": "Active adversaries can forge authenticated payloads.",
                "recommendation": "Immediately transition to HMAC-SHA256 or SHA-384."
            })
            threats.append({
                "threat": "Integrity Forgery via MD5 Collision",
                "severity": "Critical",
                "likelihood": "High",
                "impact": "Critical",
                "status": "Vulnerable",
                "recommendation": "Disallow MD5 across all security association proposals."
            })
        else:
            strengths.append(f"{authentication} provides robust collision-resistant integrity protection.")
            threats.append({
                "threat": "Integrity Tampering / Man-in-the-Middle",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "Maintained with SHA-2 family hashing."
            })

        # 3. EVALUATE DIFFIE-HELLMAN GROUP
        dh_clean = dh_group.strip()
        if dh_clean in ["Group 1", "Group 2", "DH Group 1", "DH Group 2", "DH 1", "DH 2"] or ("1024" in dh_clean and "2048" not in dh_clean) or ("768" in dh_clean):
            score -= 22
            weaknesses.append(f"{dh_group} (1024-bit or weaker MODP) is vulnerable to discrete logarithm precomputations (Logjam attack).")
            findings.append({
                "finding": f"Weak Diffie-Hellman Key Exchange ({dh_group})",
                "severity": "High",
                "explanation": "1024-bit MODP primes are susceptible to Number Field Sieve precomputation attacks by well-funded adversaries (e.g. Logjam attack on common DH primes).",
                "impact": "Adversaries intercepting IKE handshakes can decrypt session keys and subsequent ESP traffic.",
                "recommendation": "Upgrade DH Group to Group 14 (2048-bit MODP), Group 19 (256-bit ECP), or Group 20 (384-bit ECP)."
            })
            threats.append({
                "threat": "Diffie-Hellman Precomputation / Logjam",
                "severity": "High",
                "likelihood": "High",
                "impact": "Critical",
                "status": "Vulnerable",
                "recommendation": "Mandate DH Group >= 14 or Elliptic Curve DH (Group 19/20)."
            })
        elif dh_clean in ["Group 5", "DH Group 5", "DH 5", "1536"]:
            score -= 10
            weaknesses.append("DH Group 5 (1536-bit) provides marginal cryptographic strength below current 112-bit security requirements.")
            findings.append({
                "finding": "Sub-standard Diffie-Hellman Group 5 (1536-bit)",
                "severity": "Medium",
                "explanation": "Group 5 provides approximately 90-100 bits of equivalent symmetric strength, failing modern 128-bit compliance standards.",
                "impact": "Reduced resilience against cryptanalytic advances.",
                "recommendation": "Switch to DH Group 14 or Group 19/20."
            })
        else:
            strengths.append(f"{dh_group} delivers modern key agreement with strong discrete log resilience.")
            threats.append({
                "threat": "Key Exchange Eavesdropping",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "Current DH group satisfies CNSA and NIST requirements."
            })

        # 4. EVALUATE PERFECT FORWARD SECRECY (PFS)
        if not pfs:
            score -= 16
            weaknesses.append("Perfect Forward Secrecy (PFS) is disabled. Compromise of long-term credentials exposes all past session traffic.")
            findings.append({
                "finding": "Perfect Forward Secrecy (PFS) Disabled",
                "severity": "Medium",
                "explanation": "Without PFS, Phase 2 Child SAs derive session keys directly from the Phase 1 IKE master key without an independent DH exchange.",
                "impact": "If the long-term private key or initial IKE master key is compromised at any point in the future, all previously recorded VPN traffic can be retroactively decrypted.",
                "recommendation": "Enable PFS in Phase 2 / Child SA proposals using DH Group 14 or Group 19/20."
            })
            threats.append({
                "threat": "Retroactive Decryption via Master Key Compromise",
                "severity": "Medium",
                "likelihood": "Medium",
                "impact": "Critical",
                "status": "At Risk",
                "recommendation": "Enable PFS immediately to isolate cryptographic blast radius."
            })
        else:
            strengths.append("PFS is enabled; session keys are cryptographically isolated per tunnel renegotiation.")
            threats.append({
                "threat": "Past Traffic Retroactive Decryption",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "PFS ensures forward confidentiality."
            })

        # 5. EVALUATE IKE VERSION
        if ike_version == "IKEV1":
            score -= 14
            weaknesses.append("IKEv1 is legacy (RFC 2409). It lacks built-in DoS cookie protection and is prone to Aggressive Mode PSK dictionary attacks.")
            findings.append({
                "finding": "Legacy IKE Protocol Version (IKEv1)",
                "severity": "High",
                "explanation": "IKEv1 has high round-trip complexity, vulnerable Aggressive Mode handshakes that expose PSK hashes to offline dictionary attacks, and lacks modern NAT-T integration.",
                "impact": "Vulnerability to credential harvesting and handshake denial-of-service.",
                "recommendation": "Upgrade VPN gateways and client endpoints to IKEv2 (RFC 7296)."
            })
            threats.append({
                "threat": "IKEv1 Aggressive Mode PSK Cracking",
                "severity": "High",
                "likelihood": "Medium",
                "impact": "High",
                "status": "Vulnerable",
                "recommendation": "Migrate to IKEv2 or disable Aggressive Mode in favor of Main Mode."
            })
        else:
            strengths.append("IKEv2 utilized with streamlined state machine and resilient DoS cookie mechanism.")
            threats.append({
                "threat": "Handshake Flood & State Exhaustion",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "IKEv2 anti-DoS cookie verification prevents memory exhaustion."
            })

        # 6. EVALUATE REPLAY PROTECTION
        if not replay_protection:
            score -= 15
            weaknesses.append("Replay protection is disabled. The security association is vulnerable to replay attacks and state injection.")
            findings.append({
                "finding": "Anti-Replay Window Disabled",
                "severity": "High",
                "explanation": "ESP sequence number validation is turned off, allowing adversaries to capture legitimate encrypted packets and re-inject them into the network stream.",
                "impact": "Susceptible to duplicate transactions, denial of service, and TCP connection desynchronization.",
                "recommendation": "Enable IPsec Anti-Replay protection with a minimum window size of 64 or 128 packets."
            })
            threats.append({
                "threat": "Packet Replay & Sequence Injection",
                "severity": "High",
                "likelihood": "High",
                "impact": "High",
                "status": "Vulnerable",
                "recommendation": "Enable Anti-Replay window on both SA endpoints."
            })
        else:
            strengths.append("Anti-Replay sliding window active (protects against packet duplication attacks).")
            threats.append({
                "threat": "Packet Replay Attacks",
                "severity": "Low",
                "likelihood": "Low",
                "impact": "Low",
                "status": "Mitigated",
                "recommendation": "Sliding sequence window detects duplicate packets."
            })

        # 7. EVALUATE KEY LIFETIME
        if key_lifetime > 86400:
            score -= 8
            weaknesses.append(f"Excessive key lifetime ({key_lifetime} seconds / {key_lifetime // 3600}h) increases exposure window.")
            findings.append({
                "finding": "Excessive Security Association Cryptoperiod",
                "severity": "Medium",
                "explanation": "SA lifetimes exceeding 24 hours provide adversaries an extended time window to accumulate ciphertext under identical session keys.",
                "impact": "Higher vulnerability to cryptanalysis and key leakage over prolonged high-volume data streams.",
                "recommendation": "Configure Phase 2 SA rekey interval between 3,600s (1 hour) and 28,800s (8 hours)."
            })
            threats.append({
                "threat": "Cryptoperiod Key Exhaustion",
                "severity": "Medium",
                "likelihood": "Medium",
                "impact": "Medium",
                "status": "At Risk",
                "recommendation": "Set rekey timer to <= 28,800 seconds."
            })
        elif key_lifetime > 28800:
            score -= 3
            findings.append({
                "finding": "Moderate SA Lifetime Duration",
                "severity": "Low",
                "explanation": "Lifetime is slightly higher than conservative enterprise recommendations (8 hours).",
                "impact": "Minor risk under sustained multi-gigabit traffic flows.",
                "recommendation": "Consider lowering rekey period to 28,800 seconds (8 hours)."
            })

        # 8. EVALUATE VPN MODE & METADATA EXPOSURE
        if mode == "Transport":
            score -= 5
            weaknesses.append("Transport Mode exposes source and destination IP addresses in cleartext.")
            findings.append({
                "finding": "Transport Mode Active (Endpoint Metadata Exposure)",
                "severity": "Low",
                "explanation": "Transport Mode only encrypts the upper-layer payload (TCP/UDP). The original IP header remains exposed to intermediate autonomous systems.",
                "impact": "Network observers can map internal endpoint topologies and traffic patterns.",
                "recommendation": "Use Tunnel Mode for gateway-to-gateway and remote access VPN deployments."
            })
            metadata_exposure = {
                "level": "MEDIUM",
                "color": "amber",
                "score_impact": -5,
                "summary": "Original IP packet headers are visible to eavesdroppers. Intermediate ISP nodes can identify exact communicating host endpoints.",
                "exposed_fields": [
                    {"field": "Origin Host IP", "status": "EXPOSED (Plaintext)", "risk": "Medium"},
                    {"field": "Destination Host IP", "status": "EXPOSED (Plaintext)", "risk": "Medium"},
                    {"field": "Packet Size & Distribution", "status": "OBSERVABLE", "risk": "Medium"},
                    {"field": "Packet Timing & Intervals", "status": "OBSERVABLE", "risk": "Low"},
                    {"field": "Transport Protocol (ESP 50)", "status": "IDENTIFIABLE", "risk": "Low"},
                    {"field": "Payload Data", "status": "ENCRYPTED (Secure)", "risk": "None"}
                ]
            }
        else:
            strengths.append("Tunnel Mode encapsulates original IP packets within a new gateway IP header, shielding internal host addresses.")
            metadata_exposure = {
                "level": "LOW",
                "color": "emerald",
                "score_impact": 0,
                "summary": "Full encapsulation active. Inner host IP addresses and subnet architectures are hidden from external observation.",
                "exposed_fields": [
                    {"field": "Origin Host IP", "status": "PROTECTED (Encapsulated)", "risk": "None"},
                    {"field": "Destination Host IP", "status": "PROTECTED (Encapsulated)", "risk": "None"},
                    {"field": "Gateway Endpoints", "status": "VISIBLE (Public Gateway IPs)", "risk": "Low"},
                    {"field": "Packet Size & Traffic Volume", "status": "OBSERVABLE (Side-channel)", "risk": "Low"},
                    {"field": "Packet Timing & Intervals", "status": "OBSERVABLE (Traffic Analysis)", "risk": "Low"},
                    {"field": "Payload & Inner Header", "status": "ENCRYPTED (Secure)", "risk": "None"}
                ]
            }

        # Informational finding regarding IP Version
        findings.append({
            "finding": f"Protocol Environment: {ip_version}",
            "severity": "Informational",
            "explanation": f"Operating across {ip_version} stack. Native IPsec architecture fully supported.",
            "impact": "None. Cryptographic primitives function identically.",
            "recommendation": "Ensure path MTU discovery (PMTUD) and MSS clamping are configured to prevent packet fragmentation."
        })

        # CLAMP SCORE
        score = max(5, min(100, score))

        # DETERMINE RISK LEVEL
        if score >= 85:
            risk_level = "LOW"
            risk_badge = "emerald"
            risk_summary = "Robust security posture conforming to current cryptographic standards and enterprise guidelines."
        elif score >= 70:
            risk_level = "MEDIUM"
            risk_badge = "amber"
            risk_summary = "Acceptable operational baseline, but contains deprecation risks or suboptimal parameters requiring attention."
        elif score >= 45:
            risk_level = "HIGH"
            risk_badge = "orange"
            risk_summary = "Significant security vulnerabilities detected. Immediate remediation recommended to prevent eavesdropping."
        else:
            risk_level = "CRITICAL"
            risk_badge = "rose"
            risk_summary = "Critical security flaws present (e.g. broken ciphers, weak key exchange, disabled protections). Highly vulnerable to attack."

        # GENERATE RECOMMENDATIONS LIST
        recommendations = []
        for f in findings:
            if f["severity"] in ["Critical", "High", "Medium"]:
                recommendations.append(f"{f['finding']}: {f['recommendation']}")

        if not recommendations:
            recommendations.append("Configuration adheres to best practices. Perform scheduled security reviews every 6 months.")

        return {
            "score": score,
            "risk_level": risk_level,
            "risk_badge": risk_badge,
            "risk_summary": risk_summary,
            "findings": findings,
            "threat_matrix": threats,
            "strengths": strengths,
            "weaknesses": weaknesses,
            "recommendations": recommendations,
            "metadata_exposure": metadata_exposure
        }
