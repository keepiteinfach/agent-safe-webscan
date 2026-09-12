# Contributing

Contributions are welcome, especially checks that are reproducible, low-noise, and safe by default.

## A good finding needs

1. A stable rule ID.
2. Severity and confidence separated from each other.
3. Bounded evidence that does not leak secrets.
4. A concrete remediation.
5. A test fixture that proves both the positive case and a likely false-positive case.

## Not accepted

- Credential attacks or brute force.
- Exploit payload libraries.
- Internet-wide scanning features.
- Private-network bypasses.
- Features whose primary purpose is stealth or evasion.

Run `npm test` and `npm run check` before opening a PR.
