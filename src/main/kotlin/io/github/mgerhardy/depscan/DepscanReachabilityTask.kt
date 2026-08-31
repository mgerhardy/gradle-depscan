package io.github.mgerhardy.depscan

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.gradle.api.DefaultTask
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault
import java.io.File
import javax.inject.Inject

@DisableCachingByDefault(because = "Results depend on external vulnerability database")
abstract class DepscanReachabilityTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val depscanBinary: RegularFileProperty

    @get:Input
    abstract val targetType: Property<String>

    @get:Input
    abstract val profile: Property<String>

    @get:Input
    abstract val reachabilityAnalyzer: Property<String>

    @get:Input
    abstract val vdbScope: Property<String>

    @get:Input
    abstract val includeTestDependencies: Property<Boolean>

    @get:Input
    abstract val additionalArgs: ListProperty<String>

    @get:OutputDirectory
    abstract val reportsDir: DirectoryProperty

    @get:Optional
    @get:Input
    abstract val vdbHome: Property<String>

    @get:Input
    abstract val artifactDirs: ListProperty<String>

    /** Directory containing generated lock files (from DepscanLockGradleTask). */
    @get:Optional
    @get:Input
    abstract val lockFilesDir: Property<String>

    /** Transient -- set by plugin, not serialized. Used to resolve runtime deps. */
    @get:org.gradle.api.tasks.Internal
    abstract val javaProjects: ListProperty<Project>

    @TaskAction
    fun analyze() {
        val binary = depscanBinary.get().asFile.absolutePath
        val reports = reportsDir.get().asFile
        reports.mkdirs()

        val env = buildEnvironment()
        val csafFiles = mutableListOf<File>()
        val slurper = JsonSlurper()

        // Determine scan mode: lock-file based or artifact-based
        val lockDir = if (lockFilesDir.isPresent) File(lockFilesDir.get()) else null
        val hasLockFiles = lockDir != null && lockDir.exists() &&
            lockDir.walkTopDown().any { it.name == "gradle.lockfile" }

        if (hasLockFiles) {
            logger.lifecycle("Using lock-file based scanning (no compilation needed)")
            scanFromLockFiles(lockDir, binary, env, reports, csafFiles, slurper)
        } else {
            logger.lifecycle("Using artifact-based scanning (requires pre-built artifacts)")
            scanFromArtifacts(binary, env, reports, csafFiles, slurper)
        }

        if (csafFiles.isEmpty()) {
            logger.warn("No CSAF reports produced. Ensure dependencies are resolved or projects are built.")
            return
        }

        // Collect runtime deps for test-scope filtering
        val runtimeDeps = if (!includeTestDependencies.get()) {
            if (javaProjects.isPresent && javaProjects.get().isNotEmpty()) {
                RuntimeDependencyResolver.collectRuntimeDeps(javaProjects.get(), logger)
            } else if (hasLockFiles) {
                // Lock files already contain only runtime deps per configuration
                // so filtering is less critical, but we can still extract them
                RuntimeDependencyResolver.collectRuntimeDepsFromLockFiles(lockDir, logger)
            } else {
                val deps = RuntimeDependencyResolver.collectRuntimeDepsFromFiles(artifactDirs.get(), logger)
                deps.ifEmpty { null }
            }
        } else {
            null
        }

        // Merge reports
        val mergedReport = File(reports, "depscan-merged-reachability.csaf.json")
        CsafReportMerger.merge(csafFiles, mergedReport, runtimeDeps, logger)
        logger.lifecycle("Merged report: ${mergedReport.absolutePath}")
    }

    /**
     * Scan using generated lock files.  We generate CycloneDX BOMs directly
     * from the lock file content (bypassing cdxgen which cannot read bare
     * gradle.lockfile without a build.gradle) and pass each BOM to depscan
     * via --bom-dir for reachability analysis.
     */
    private fun scanFromLockFiles(
        lockDir: File,
        binary: String,
        env: Map<String, String>,
        reports: File,
        csafFiles: MutableList<File>,
        slurper: JsonSlurper
    ) {
        val bomFiles = LockFileBomGenerator.generateBomsFromLockDir(lockDir)
        logger.lifecycle("Generated ${bomFiles.size} BOMs from lock files")

        for (bomFile in bomFiles) {
            val projectName = bomFile.parentFile.relativeTo(lockDir).path
                .replace(File.separator, "-")
                .ifEmpty { "root" }

            logger.lifecycle("[$projectName] Running reachability analysis (${bomFile.length() / 1024}KB BOM)...")
            runReachabilityAnalysis(projectName, bomFile, binary, env, reports, csafFiles, slurper)
        }
    }

    /**
     * Original artifact-based scanning path -- walks build/libs/ directories
     * for JARs/WARs.
     */
    private fun scanFromArtifacts(
        binary: String,
        env: Map<String, String>,
        reports: File,
        csafFiles: MutableList<File>,
        slurper: JsonSlurper
    ) {
        val artifacts = findArtifacts()
        if (artifacts.isEmpty()) {
            logger.warn("No scannable artifacts found.")
            logger.warn("Run with lock files: ./gradlew depscanLockGradle depscanReachability")
            return
        }

        for ((projectName, artifactFile) in artifacts) {
            logger.lifecycle("[$projectName] Analyzing ${artifactFile.name}...")

            // Step 1: Generate BOM
            val bomDir = File.createTempFile("depscan-bom-$projectName-", "").apply { delete(); mkdirs() }
            try {
                val bomArgs = mutableListOf(
                    binary,
                    "-t", targetType.get(),
                    "-i", artifactFile.absolutePath,
                    "--reports-dir", bomDir.absolutePath,
                    "--vdb-scope", vdbScope.get(),
                    "--no-banner",
                    "--no-vuln-table"
                )
                val bomResult = execOps.exec { spec ->
                    spec.commandLine(bomArgs)
                    spec.environment(env)
                    spec.isIgnoreExitValue = true
                    spec.standardOutput = java.io.OutputStream.nullOutputStream()
                }
                if (bomResult.exitValue != 0) {
                    logger.warn("[$projectName] BOM generation exited with code ${bomResult.exitValue}")
                }

                val bomFile = bomDir.listFiles()?.firstOrNull {
                    it.name.startsWith("sbom") && it.name.endsWith(".cdx.json")
                }
                if (bomFile == null) {
                    logger.warn("[$projectName] No BOM generated, skipping")
                    continue
                }

                runReachabilityAnalysis(projectName, bomFile, binary, env, reports, csafFiles, slurper)
            } finally {
                bomDir.deleteRecursively()
            }
        }
    }

    /**
     * Common reachability analysis: patches BOM lifecycle if needed, runs depscan
     * reachability, collects CSAF output.
     */
    private fun runReachabilityAnalysis(
        projectName: String,
        bomFile: File,
        binary: String,
        env: Map<String, String>,
        reports: File,
        csafFiles: MutableList<File>,
        slurper: JsonSlurper
    ) {
        // Patch lifecycle to post-build
        val pbDir = File.createTempFile("depscan-pb-$projectName-", "").apply { delete(); mkdirs() }
        try {
            @Suppress("UNCHECKED_CAST")
            val bomData = slurper.parseText(bomFile.readText()) as MutableMap<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val metadata = bomData.getOrPut("metadata") { mutableMapOf<String, Any?>() }
                as MutableMap<String, Any?>
            metadata["lifecycles"] = listOf(mapOf("phase" to "post-build"))
            val patchedBom = File(pbDir, bomFile.name.replace("sbom-", "sbom-postbuild-"))
            patchedBom.writeText(JsonOutput.toJson(bomData))

            // Run reachability analysis
            val resultsDir = File(reports, projectName)
            resultsDir.mkdirs()
            val reachArgs = mutableListOf(
                binary,
                "--profile", profile.get(),
                "--reachability-analyzer", reachabilityAnalyzer.get(),
                "--csaf",
                "-t", targetType.get(),
                "--bom-dir", pbDir.absolutePath,
                "--reports-dir", resultsDir.absolutePath,
                "--vdb-scope", vdbScope.get(),
                "--no-banner",
                "--no-vuln-table"
            )
            reachArgs.addAll(additionalArgs.get())

            val reachResult = execOps.exec { spec ->
                spec.commandLine(reachArgs)
                spec.environment(env)
                spec.isIgnoreExitValue = true
                spec.standardOutput = java.io.OutputStream.nullOutputStream()
            }
            if (reachResult.exitValue != 0) {
                logger.warn("[$projectName] Reachability analysis exited with code ${reachResult.exitValue}")
            }

            val csafFile = resultsDir.listFiles()?.firstOrNull { it.name.endsWith(".csaf.json") }
            if (csafFile != null) {
                csafFiles.add(csafFile)
                logger.lifecycle("[$projectName] CSAF report generated: ${csafFile.name}")
            } else {
                logger.warn("[$projectName] No CSAF output produced")
            }
        } finally {
            pbDir.deleteRecursively()
        }
    }

    private fun findArtifacts(): List<Pair<String, File>> {
        val results = mutableListOf<Pair<String, File>>()
        for (dir in artifactDirs.get()) {
            val libsDir = File(dir)
            if (!libsDir.exists()) continue
            val projectName = libsDir.parentFile.parentFile?.name ?: libsDir.parentFile.name
            val artifact = DepscanScanTask.pickArtifact(libsDir) ?: continue
            results.add(projectName to artifact)
        }
        return results
    }

    private fun buildEnvironment(): Map<String, String> {
        val env = mutableMapOf<String, String>()
        env.putAll(System.getenv())
        if (vdbHome.isPresent) {
            env["VDB_HOME"] = vdbHome.get()
            File(vdbHome.get()).mkdirs()
        }
        return env
    }
}
