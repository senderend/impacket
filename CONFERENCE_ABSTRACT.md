# Show Me the GUI: Harvesting Secrets Interactively Through NTLM Relay to Enterprise Vaults

## Abstract

Most organizations deploy password vaults and privileged access management solutions with Integrated Windows Authentication enabled—a default configuration that allows transparent authentication via NTLM. While NTLM relay attacks are well-established for SMB and RPC protocols, generic HTTP NTLM endpoints have remained largely unexplored and underutilized as relay targets.

This talk presents techniques for relaying NTLM authentication to HTTP-based services including CyberArk, Delinea Secret Server, BeyondTrust Password Safe, and other enterprise credential management platforms. Through improvements to existing relay tooling, we demonstrate how an attacker can harvest user sessions from network artifacts, assume their authenticated context via SOCKS proxy, and interact with password vaults through their native web interface—enabling direct access to secrets protected by those systems.

The attack flow mirrors legitimate enterprise traffic, avoiding many detection mechanisms while providing operators the ability to execute the full authentication workflow of a compromised user. We'll discuss practical attack chains including initial session harvesting, multiple relay targets, and extraction of credentials from services relied upon for security.

This research uncovers a significant gap in how these widely-deployed systems are secured against relay attacks and introduces operational techniques for exploiting it.

## Key Takeaways

- Default configurations enable this attack surface
- Security tools themselves become the target
- Network detection evasion through legitimate-looking auth traffic
- Browser-based interaction enables full GUI access vs. CLI-only exploitation
- Affects multiple vendors and widely-deployed enterprise products

## Affected Products

- CyberArk
- Delinea Secret Server
- BeyondTrust Password Safe
- IBM Verify Privilege Vault
- Thycotic Secret Server
- OneIdentity Password Manager
- Passwordstate
- SharePoint
- Microsoft Identity Manager
- Beyond Trust Privileged Identity
- ManageEngine PAM360
- And others supporting Integrated Windows Authentication
