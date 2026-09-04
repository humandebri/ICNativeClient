# Security Policy

## Supported versions

Security fixes are provided for the latest `0.2.x` release line. The `0.1.x` line does not verify IC certificates or query signatures and is not supported for security-sensitive use.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub Private Vulnerability Reporting for this repository and include affected versions, impact, reproduction steps, and any proposed remediation.

Private Vulnerability Reporting must be enabled before the repository is made public. Until that reporting channel is confirmed working, OSS publication is blocked rather than asking reporters to guess an undocumented private contact method.

Please allow a reasonable period for acknowledgement, validation, remediation, and coordinated disclosure. Do not access data or systems that you do not own while testing.

## Security boundary

`queryRaw`, `callRaw`, and `poll` verify the relevant IC node signature or certificate. `unsafeQueryRaw` intentionally does not authenticate a query response and must not be used where integrity matters. Non-mainnet deployments must provide an independently trusted root key through `ICTrustRoot.custom`.

Enabling and testing GitHub Private Vulnerability Reporting is a repository setting and remains a manual pre-publication task.
