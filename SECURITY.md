# Security Policy

## Supported versions

Security fixes are provided for the latest `0.7.x` release line. Releases before `0.3.0` do not verify IC certificates or query signatures and are not supported for security-sensitive use.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub Private Vulnerability Reporting for this repository and include affected versions, impact, reproduction steps, and any proposed remediation.

Please allow a reasonable period for acknowledgement, validation, remediation, and coordinated disclosure. Do not access data or systems that you do not own while testing.

## Security boundary

`queryRaw`, `callRaw`, and `poll` verify the relevant IC node signature or certificate. `unsafeQueryRaw` intentionally does not authenticate a query response and must not be used where integrity matters. Non-mainnet deployments must provide an independently trusted root key through `ICTrustRoot.custom`.
