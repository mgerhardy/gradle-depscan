# gradle-depscan

A Gradle plugin that wraps [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) for vulnerability scanning with **reachability analysis**. Unlike tools that only report CVE presence, this plugin determines whether vulnerable code paths are actually reachable in your application -- reducing false positives and letting you focus on real risks.

## Features

- **Auto-downloads** the depscan binary (cached across builds)
- **Basic vulnerability scanning** of built JARs/WARs
- **Reachability analysis** -- classifies each CVE as reachable or not
- **Test-scope filtering** -- auto-excludes CVEs in test-only dependencies (configurable)
- **Multi-project support** -- scans all Java subprojects, merges results into a single CSAF VEX report
- **CSAF VEX output** -- standard format consumable by DefectDojo and other security tools

## Quick Start

Apply the plugin to your root `build.gradle.kts`:

```kotlin
plugins {
    id("io.github.mgerhardy.depscan") version "0.1.0"
}
```

Run a basic vulnerability scan:

```bash
./gradlew depscanScan
```

Run the full reachability analysis:

```bash
./gradlew depscanReachability
```

Reports are written to `build/reports/depscan/`.

## Configuration

```kotlin
depscan {
    // dep-scan version to download (default: "6.3.0")
    version.set("6.3.0")

    // Use a local depscan binary instead of downloading
    // binaryPath.set(file("/usr/local/bin/depscan"))

    // Target type (default: "java")
    targetType.set("java")

    // Analysis profile (default: "research")
    profile.set("research")

    // Reachability analyzer (default: "SemanticReachability")
    reachabilityAnalyzer.set("SemanticReachability")

    // Vulnerability DB scope (default: "app" -- application-level only)
    vdbScope.set("app")

    // Include test dependencies in analysis (default: false)
    // When false, CVEs in test-only deps are reclassified as not-affected
    includeTestDependencies.set(false)

    // Exclude specific subprojects from scanning
    excludeProjects.set(listOf("integration-tests", "test-fixtures"))

    // Extra CLI args for basic scan
    additionalScanArgs.set(listOf("--no-vuln-table"))

    // Extra CLI args for reachability analysis
    additionalReachabilityArgs.set(listOf())

    // Report output directory (default: build/reports/depscan/)
    reportsDir.set(layout.buildDirectory.dir("reports/depscan"))

    // Vulnerability DB cache (default: ~/.gradle/caches/depscan/vdb/)
    // vdbHome.set(layout.buildDirectory.dir("depscan-vdb"))
}
```

## Tasks

| Task | Description |
|---|---|
| `depscanDownload` | Downloads the depscan binary (cached, skipped if `binaryPath` is set) |
| `depscanScan` | Basic vulnerability scan against built artifacts |
| `depscanReachability` | Full reachability analysis pipeline with CSAF VEX output |
| `depscanFullScan` | Convenience alias for `depscanReachability` |

### Task Dependencies

- `depscanScan` and `depscanReachability` both depend on `depscanDownload` and each subproject's `assemble` task
- `depscanFullScan` depends on `depscanReachability`

## How Reachability Analysis Works

The reachability pipeline runs per Java subproject:

1. **Generate SBOM** -- depscan scans the built WAR/JAR and produces a CycloneDX BOM with framework-type annotations
2. **Patch lifecycle** -- the BOM's lifecycle metadata is set to `post-build`, enabling binary-level reachability classification
3. **Classify reachability** -- depscan re-processes the BOM using `SemanticReachability` analysis, producing a CSAF VEX document
4. **Filter test dependencies** -- CVEs in packages not present in any subproject's `runtimeClasspath` are reclassified as `known_not_affected`
5. **Merge reports** -- per-project CSAF reports are merged into a single deduplicated report

The final report classifies each vulnerability as:
- `known_affected` -- the vulnerable code path is reachable
- `known_not_affected` -- the vulnerability is present but not reachable, or the dependency is test-only

## CI Integration

```yaml
# GitHub Actions
- name: Build
  run: ./gradlew assemble

- name: Run depscan reachability
  run: ./gradlew depscanReachability

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: depscan-report
    path: build/reports/depscan/depscan-merged-reachability.csaf.json
```

## Requirements

- Gradle 7.0+
- Java 17+
- Linux or macOS (amd64 or arm64)

## License

Apache License 2.0
