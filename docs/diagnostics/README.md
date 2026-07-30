# Diagnostic patterns

| Repository/template                        | Quality mechanism                                                                                                                             | Why it is useful                                                                                                                                                                        |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **scikit-learn — `bug_report.yml`**        | Impact statement → minimal reproducer → expected/actual result → complete traceback → environment → proposed diagnosis                        | Strongest overall example. It explicitly demands copy-paste execution without external data and asks why the defect matters before maintainers invest effort. citeturn850330view0    |
| **Electron — `bug_report.yml`**            | Preflight attestations → supported version → OS/architecture → last-known-good version → upstream Chromium probe → standalone Fiddle testcase | Excellent active-diagnosis workflow. The Chromium comparison and last-working-version fields help isolate ownership and regression boundaries before submission. citeturn325453view1 |
| **pandas — `bug_report.yaml`**             | Duplicate search → latest-release confirmation → main-branch confirmation → minimal reproducible example → `show_versions()`                  | Compact but strict. Particularly useful where reporters can cheaply test both release and development revisions. citeturn325453view0                                                 |
| **Home Assistant Core — `bug_report.yml`** | Current/last-working version → installation type → subsystem identification → documentation link → diagnostics bundle → YAML/log evidence     | Good model for systems where structured diagnostic exports are more useful than a handwritten reproduction alone. citeturn224977view0                                                |
| **Kubernetes — `bug-report.yaml`**         | Minimal precise reproduction → Kubernetes version → cloud provider → OS → install tooling → runtime and plugin versions                       | Strong environment-envelope template for distributed or platform-dependent failures. citeturn777084view1                                                                             |
| **Rust — `regression.md`**                 | Minimal code → expected/observed result → last-known-good version → failing version → verbose compiler identity → backtrace                   | A focused regression-localization template rather than a generic bug form. Useful as a separate issue class. citeturn777084view2                                                     |
| **pytest — `1_bug_report.md`**             | Detailed description → dependency inventory → tool/OS versions → minimal example                                                              | A lightweight baseline. It captures the essential evidence but does not enforce an active pre-submission workflow. citeturn777084view0                                               |

## Best patterns to extract

The highest-signal templates do not merely ask reporters to check boxes. They construct a small diagnostic control loop:

```text
classify
  → verify supported/current state
  → reproduce
  → minimize
  → compare against a boundary
  → capture environment
  → attach machine-generated evidence
  → submit
```

A composite quality gate would therefore contain:

1. **Eligibility and routing**
   - Correct repository and component
   - Bug rather than support request, feature request, or upstream defect
   - Security reports redirected privately

2. **Active probes**
   - Reproduced on the latest supported release
   - Optionally reproduced on `main`
   - Compared with the last-known-good version
   - Tested against an upstream or adjacent implementation where ownership is ambiguous

3. **Evidence contract**
   - Minimal, independently executable reproduction
   - Exact invocation
   - Expected and observed outputs
   - Complete diagnostic output rather than excerpts
   - Machine-generated environment manifest

4. **Localization metadata**
   - First failing and last working versions
   - Component/subsystem
   - Platform, architecture, runtime and dependency versions
   - Whether the failure survives configuration removal or isolation

5. **Submission attestations**
   - Existing issues and documentation searched
   - Sensitive data removed
   - Reproduction still works from the submitted artifact

GitHub Issue Forms support required inputs, dropdowns and checkboxes, making these fields enforceable at form-submission time. However, required attestations only confirm that a box was checked; evidence-bearing fields such as commands, outputs, revisions and reproducer links provide the stronger quality gate. citeturn780755search2turn780755search16

**Best starting combination:** scikit-learn’s reproducer discipline, Electron’s differential probes, pandas’ release-versus-main verification, and Home Assistant’s generated diagnostics.
