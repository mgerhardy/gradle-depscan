package io.github.mgerhardy.depscan

import groovy.json.JsonOutput
import java.io.File
import java.util.UUID

/**
 * Generates CycloneDX BOMs directly from Gradle lock files.
 *
 * This bypasses cdxgen entirely -- cdxgen cannot parse a bare gradle.lockfile
 * without an accompanying build.gradle.  We parse the lock file format
 * (`group:name:version=configName`) ourselves and emit a minimal but valid
 * CycloneDX 1.5 JSON BOM that depscan can consume.
 */
object LockFileBomGenerator {

    data class Dependency(val group: String, val name: String, val version: String)

    /**
     * Parse a single gradle.lockfile and return the unique dependencies.
     * Only runtime-relevant configurations are included to avoid inflating
     * the BOM with annotation processors or test-only libraries.
     */
    fun parseLockFile(lockFile: File, runtimeOnly: Boolean = true): Set<Dependency> {
        val runtimeConfigs = if (runtimeOnly) {
            setOf(
                "runtimeClasspath", "productionRuntimeClasspath", "runtimeOnly",
                "implementation", "api", "compileClasspath"
            )
        } else {
            null // accept all
        }

        val deps = mutableSetOf<Dependency>()
        for (line in lockFile.readLines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed == "empty=") continue
            val eqIdx = trimmed.indexOf('=')
            if (eqIdx < 0) continue
            val coord = trimmed.substring(0, eqIdx)
            val configName = trimmed.substring(eqIdx + 1)

            if (runtimeConfigs != null && runtimeConfigs.none { configName.contains(it, ignoreCase = true) }) {
                continue
            }

            val parts = coord.split(":")
            if (parts.size >= 3) {
                deps.add(Dependency(parts[0], parts[1], parts[2]))
            }
        }
        return deps
    }

    /**
     * Generate a CycloneDX 1.5 JSON BOM from a set of dependencies.
     */
    fun generateBom(
        dependencies: Set<Dependency>,
        projectName: String = "gradle-project"
    ): String {
        val components = dependencies.sortedWith(compareBy({ it.group }, { it.name })).map { dep ->
            mapOf(
                "type" to "library",
                "group" to dep.group,
                "name" to dep.name,
                "version" to dep.version,
                "purl" to "pkg:maven/${dep.group}/${dep.name}@${dep.version}",
                "bom-ref" to "pkg:maven/${dep.group}/${dep.name}@${dep.version}"
            )
        }

        val bom = linkedMapOf(
            "bomFormat" to "CycloneDX",
            "specVersion" to "1.5",
            "version" to 1,
            "serialNumber" to "urn:uuid:${UUID.randomUUID()}",
            "metadata" to mapOf(
                "component" to mapOf(
                    "type" to "application",
                    "name" to projectName,
                    "bom-ref" to projectName
                ),
                "lifecycles" to listOf(
                    mapOf("phase" to "post-build")
                )
            ),
            "components" to components
        )

        return JsonOutput.prettyPrint(JsonOutput.toJson(bom))
    }

    /**
     * Process a lock file directory: for each gradle.lockfile found, generate
     * a CycloneDX BOM and write it next to the lock file as `sbom-java.cdx.json`.
     *
     * Returns the list of generated BOM files.
     */
    fun generateBomsFromLockDir(lockDir: File, runtimeOnly: Boolean = true): List<File> {
        val bomFiles = mutableListOf<File>()
        lockDir.walkTopDown()
            .filter { it.name == "gradle.lockfile" }
            .forEach { lockFile ->
                val deps = parseLockFile(lockFile, runtimeOnly)
                if (deps.isEmpty()) return@forEach

                val projectName = lockFile.parentFile.relativeTo(lockDir).path
                    .replace(File.separator, "-")
                    .ifEmpty { "root" }

                val bomContent = generateBom(deps, projectName)
                val bomFile = File(lockFile.parentFile, "sbom-java.cdx.json")
                bomFile.writeText(bomContent)
                bomFiles.add(bomFile)
            }
        return bomFiles
    }
}
