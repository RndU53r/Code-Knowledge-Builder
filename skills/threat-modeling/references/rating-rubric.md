# Likelihood and impact rubric

**Likelihood**
- high: reachable by an unauthenticated or low-privilege actor with no special conditions, and exploitation is well known.
- medium: needs authentication, a specific role, a non-default config, or an internal network position.
- low: needs several unlikely conditions, or the evidence is partial.

**Impact**
- high: compromise of credentials, broad PII or payment data, remote code execution, cross-tenant access, or integrity loss on core business data.
- medium: limited data exposure, a single user's data, a service-level DoS, or privilege gain inside one component.
- low: information leaks with little value, or nuisance-level DoS.

**Priority** = the higher of the two, raised one level when both are high and lowered one level when both are low.

**Confidence** (separate from rating): high when source→sink are both cited and nothing in between sanitizes; medium when one hop is inferred; low when it's a pattern match only.
