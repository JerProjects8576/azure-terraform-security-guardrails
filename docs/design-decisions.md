# Design decisions

## 1. Why check the code instead of the running environment?

**Choice:** the rules run on Terraform files in the pipeline.

**Why:** a mistake found in a pull request costs a minute to fix. The same
mistake found after deployment may already have exposed data. This is often
called "shift left": move the check as early as possible.

**Trade-off:** it only sees what is in the code. Manual changes in the portal
need a runtime tool such as Azure Policy or Defender for Cloud. The two
complement each other.

## 2. Why write rules when scanners like Checkov exist?

**Choice:** a small set of custom rules, next to (not instead of) a standard
scanner. My Terraform project uses Checkov in its own pipeline.

**Why:** every organisation has rules of its own that no generic scanner knows:
allowed regions, naming, which IP ranges count as "internal". Writing rules
shows how those scanners work underneath and how to extend them. It also
forces a decision for each rule on *why* it matters, instead of accepting a
list.

## 3. Why Open Policy Agent and Rego?

**Choice:** Rego rules, run with Conftest.

**Why:** OPA is an open standard used well beyond Terraform - Kubernetes
admission control, API authorisation, CI pipelines. The same language and
skills carry over. Azure Policy for Kubernetes is built on OPA Gatekeeper.

**Trade-off:** Rego reads differently from ordinary programming languages. To
keep the rules approachable, each one is short, has a comment explaining the
attack, and shares a few helpers in `lib.rego`.

## 4. Every rule starts from an attack

**Choice:** each rule documents what an attacker could do, and maps to a MITRE
ATT&CK technique.

**Why:** "the scanner says so" does not convince a developer to change
anything. "Anyone on the internet can download this storage account" does. It
also forces a rule to earn its place: if the attack cannot be described, the
rule probably should not exist.

## 5. Missing settings are judged by the provider's default

**Choice:** a rule fails when a setting is absent *and* the default is
insecure (for example public blob access), and passes when the default is
already secure (for example TLS 1.2 on storage).

**Why:** most real misconfigurations are not something someone typed, but
something they left out. A rule that only looks for `= true` misses those.

**Trade-off:** defaults can change between provider versions. The rules are
written for `azurerm` 4.x and the unit tests state each assumption explicitly.

## 6. Unknown values become a warning, not a guess

**Choice:** when a setting comes from a variable, the rule neither fails nor
passes; a separate AZ-000 warning is raised.

**Why:** failing would punish correct, parameterised code. Passing would give
false confidence. An honest "I cannot tell from here" is the right answer.

**What would solve it:** scanning the JSON output of `terraform plan`, where
all values are resolved. That needs cloud credentials in the pipeline, so it
is the natural next step rather than part of this version.

## 7. The rules are tested, including with mutation checks

**Choice:** unit tests per rule, two full example environments, and a script
that compares the rules that fired with an expected list.

**Why:** a security check that silently stops working is dangerous, because
everyone still trusts the green tick. During development, rules were broken
on purpose one by one to confirm that the tests go red each time.

## 8. The scanner itself is pinned and verified

**Choice:** the pipeline downloads a fixed Conftest version and checks its
SHA-256 hash before running it.

**Why:** a security tool that is fetched as "latest" without verification is
itself a supply-chain risk.

## What I would add next

- Scan the `terraform plan` JSON to resolve variables and modules.
- More resource types: AKS, PostgreSQL, Cosmos DB, role assignments that are
  too broad (for example Owner on a subscription).
- An exception mechanism: a documented, reviewed way to accept a finding for
  one resource, with an expiry date.
- Publish the rules as a versioned bundle, so other repositories pin a release.
