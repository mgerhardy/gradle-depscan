package io.github.mgerhardy.depscan

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.gradle.api.logging.Logger
import java.io.File

/**
 * Merges multiple CSAF VEX reports into one, deduplicating by CVE ID.
 * Optionally reclassifies test-only dependencies as known_not_affected.
 */
object CsafReportMerger {

    /**
     * Merge CSAF reports and write to outputFile.
     *
     * @param csafFiles list of per-project CSAF VEX JSON files
     * @param outputFile where to write the merged report
     * @param runtimeDeps if non-null, packages NOT in this set are reclassified as test-only
     * @param logger Gradle logger
     */
    fun merge(
        csafFiles: List<File>,
        outputFile: File,
        runtimeDeps: Set<String>?,
        logger: Logger
    ) {
        val slurper = JsonSlurper()
        val seenCves = mutableSetOf<String>()
        val mergedVulns = mutableListOf<Map<*, *>>()
        var template: MutableMap<*, *>? = null
        var testOnlyCount = 0

        for (file in csafFiles) {
            if (!file.exists()) continue
            @Suppress("UNCHECKED_CAST")
            val data = slurper.parseText(file.readText()) as? MutableMap<String, Any?> ?: continue
            if (template == null) {
                template = data
            }
            val vulns = data["vulnerabilities"] as? List<*> ?: continue
            for (item in vulns) {
                @Suppress("UNCHECKED_CAST")
                val vuln = item as? MutableMap<String, Any?> ?: continue
                val cve = vuln["cve"] as? String ?: continue
                if (cve in seenCves) continue
                seenCves.add(cve)

                if (runtimeDeps != null) {
                    val pkgName = extractPackageName(vuln)
                    if (pkgName != null && pkgName !in runtimeDeps) {
                        markTestOnly(vuln)
                        testOnlyCount++
                    }
                }
                mergedVulns.add(vuln)
            }
        }

        if (template == null) {
            logger.warn("No CSAF reports to merge")
            return
        }

        @Suppress("UNCHECKED_CAST")
        (template as MutableMap<String, Any?>)["vulnerabilities"] = mergedVulns
        outputFile.parentFile.mkdirs()
        outputFile.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(template)))

        logger.lifecycle("Merged ${mergedVulns.size} vulnerabilities from ${csafFiles.size} reports")
        if (testOnlyCount > 0) {
            logger.lifecycle("  $testOnlyCount vulnerabilities reclassified as test-only (not in runtime classpath)")
        }
    }

    /**
     * Extract group:name from a vulnerability's product tree.
     */
    @Suppress("UNCHECKED_CAST")
    private fun extractPackageName(vuln: Map<String, Any?>): String? {
        val productTree = vuln["product_tree"] as? Map<String, Any?> ?: return null
        val branches = productTree["branches"] as? List<*> ?: return null
        for (branch in branches) {
            val b = branch as? Map<String, Any?> ?: continue
            val name = b["name"] as? String ?: continue
            val parts = name.split(":")
            if (parts.size >= 2) {
                return "${parts[0]}:${parts[1]}"
            }
        }
        // Fallback: check notes
        val notes = vuln["notes"] as? List<*> ?: return null
        for (note in notes) {
            val n = note as? Map<String, Any?> ?: continue
            val text = n["text"] as? String ?: continue
            if (":" in text) {
                val parts = text.split(":")
                if (parts.size >= 2 && "." in parts[0]) {
                    return "${parts[0]}:${parts[1]}"
                }
            }
        }
        return null
    }

    /**
     * Reclassify a vulnerability as known_not_affected due to test-only scope.
     */
    @Suppress("UNCHECKED_CAST")
    private fun markTestOnly(vuln: MutableMap<String, Any?>) {
        val ps = vuln.getOrPut("product_status") { mutableMapOf<String, Any?>() } as MutableMap<String, Any?>
        val affected = ps.remove("known_affected") as? List<*> ?: emptyList<Any>()
        val notAffected = ps.getOrDefault("known_not_affected", emptyList<Any>()) as List<*>
        ps["known_not_affected"] = notAffected + affected

        val threats = vuln.getOrPut("threats") { mutableListOf<Any>() } as MutableList<Any>
        threats.add(
            mapOf(
                "category" to "impact",
                "details" to "Dependency is test-scoped (testImplementation/testCompileOnly); " +
                    "not present in the production container image."
            )
        )
    }
}
