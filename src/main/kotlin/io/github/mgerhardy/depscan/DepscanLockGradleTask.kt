package io.github.mgerhardy.depscan

import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.inject.Inject

/**
 * Generates Gradle dependency lock files for all Gradle builds found under
 * the scan target directory.  Each included build is resolved in a separate
 * Gradle process using an init script that walks every resolvable
 * configuration and writes a standard `gradle.lockfile`.
 *
 * This avoids compiling any code -- only Gradle's dependency resolution
 * engine is exercised.  The resulting lock files are consumed by depscan
 * (via cdxgen) to produce accurate SBOMs that include all transitive
 * dependencies.
 */
@CacheableTask
abstract class DepscanLockGradleTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {

    @get:Internal
    abstract val scanTarget: DirectoryProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val buildScriptFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val maxParallelLocks: Property<Int>

    @get:Input
    abstract val excludeProjects: ListProperty<String>

    @get:Input
    abstract val perProjectTimeoutSeconds: Property<Long>

    companion object {
        private val SKIP_DIRS = setOf(".git", ".gradle", "node_modules", "build", ".idea", ".kotlin")
    }

    @TaskAction
    fun generate() {
        val root = scanTarget.get().asFile
        val outDir = outputDir.get().asFile
        val excluded = excludeProjects.get().toSet()
        val timeout = perProjectTimeoutSeconds.get()

        if (outDir.exists()) outDir.deleteRecursively()
        outDir.mkdirs()

        val gradleProjects = root.walk()
            .onEnter { it.name !in SKIP_DIRS }
            .filter { it.name == "settings.gradle" || it.name == "settings.gradle.kts" }
            .map { it.parentFile }
            .filter { dir ->
                val rel = dir.relativeTo(root).path.ifEmpty { "." }
                rel !in excluded
            }
            .toList()

        if (gradleProjects.isEmpty()) {
            logger.lifecycle("No Gradle projects found in $root")
            return
        }

        val sourceWrapperDir = gradleProjects
            .map { File(it, "gradle${File.separator}wrapper") }
            .firstOrNull {
                File(it, "gradle-wrapper.jar").exists() &&
                    File(it, "gradle-wrapper.properties").exists()
            }

        if (sourceWrapperDir == null) {
            logger.warn("No complete Gradle wrapper found. Cannot generate lock files.")
            return
        }

        val sourceJar = File(sourceWrapperDir, "gradle-wrapper.jar")
        val sourceProps = File(sourceWrapperDir, "gradle-wrapper.properties")
        val isWindows = System.getProperty("os.name").lowercase().contains("windows")
        val sourceGradlew = sourceWrapperDir.parentFile.let { p ->
            if (isWindows) File(p, "gradlew.bat") else File(p, "gradlew")
        }

        val initScript = File.createTempFile("depscan-lock", ".gradle")
        val dollar = "$"
        val outDirPath = outDir.absolutePath.replace("\\", "/")
        initScript.writeText(
            """
            allprojects {
                task depscanGenerateLockfile {
                    doLast {
                        def lockLines = new TreeSet<String>()
                        configurations.findAll { it.canBeResolved }.each { conf ->
                            try {
                                conf.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { dep ->
                                    lockLines.add("${dollar}{dep.moduleGroup}:${dollar}{dep.moduleName}:${dollar}{dep.moduleVersion}="+conf.name)
                                }
                            } catch (Exception e) {
                            }
                        }
                        if (!lockLines.isEmpty()) {
                            def relativePath = rootDir.toPath().relativize(projectDir.toPath()).toString()
                            if (relativePath.isEmpty()) relativePath = rootProject.name
                            def targetDir = new File("$outDirPath", relativePath)
                            targetDir.mkdirs()
                            def lockFile = new File(targetDir, "gradle.lockfile")
                            def content = new StringBuilder()
                            content.append("# This is a Gradle generated file for dependency locking.\n")
                            content.append("# Manual edits can mess up your build.\n")
                            content.append("# This file is expected to be part of source control.\n")
                            lockLines.each { content.append(it).append("\n") }
                            content.append("empty=\n")
                            lockFile.text = content.toString()
                        }
                    }
                }
            }
            """.trimIndent()
        )

        val parallel = maxParallelLocks.get().coerceAtLeast(1)
        val executor = Executors.newFixedThreadPool(parallel)

        for (projectDir in gradleProjects) {
            executor.submit {
                try {
                    val gradlew =
                        if (isWindows) File(projectDir, "gradlew.bat")
                        else File(projectDir, "gradlew")

                    if (!gradlew.exists()) {
                        if (sourceGradlew.exists()) {
                            sourceGradlew.copyTo(gradlew, overwrite = true)
                        } else {
                            logger.warn("  Skipping ${projectDir.relativeTo(root)}: no gradlew")
                            return@submit
                        }
                    }

                    val wrapperDir = File(projectDir, "gradle${File.separator}wrapper")
                    wrapperDir.mkdirs()
                    val wrapperJar = File(wrapperDir, "gradle-wrapper.jar")
                    val wrapperProps = File(wrapperDir, "gradle-wrapper.properties")
                    if (!wrapperJar.exists()) sourceJar.copyTo(wrapperJar, overwrite = true)
                    if (!wrapperProps.exists()) sourceProps.copyTo(wrapperProps, overwrite = true)
                    if (!isWindows) gradlew.setExecutable(true)

                    val label = projectDir.relativeTo(root).path.ifEmpty { "." }
                    logger.lifecycle("Resolving dependencies in $label")
                    val process = ProcessBuilder(
                        gradlew.absolutePath,
                        "--init-script", initScript.absolutePath,
                        "depscanGenerateLockfile",
                        "--no-daemon",
                        "--console=plain"
                    ).directory(projectDir)
                        .redirectErrorStream(false)
                        .start()

                    val stdoutFuture = java.util.concurrent.CompletableFuture.supplyAsync {
                        process.inputStream.bufferedReader().readText()
                    }
                    val stderrFuture = java.util.concurrent.CompletableFuture.supplyAsync {
                        process.errorStream.bufferedReader().readText()
                    }

                    val finished = process.waitFor(timeout, TimeUnit.SECONDS)
                    if (!finished) {
                        process.destroyForcibly()
                        stdoutFuture.cancel(true)
                        stderrFuture.cancel(true)
                        logger.warn("  Timed out in $label after ${timeout}s")
                        return@submit
                    }
                    if (process.exitValue() != 0) {
                        val errMsg = stderrFuture.get().lines()
                            .filter {
                                it.isNotBlank() &&
                                    !it.startsWith("Picked up JAVA_TOOL_OPTIONS")
                            }
                            .firstOrNull() ?: "exit code ${process.exitValue()}"
                        logger.warn("  Failed in $label: $errMsg")
                    }
                } catch (e: Exception) {
                    logger.warn("  Error in ${projectDir.relativeTo(root)}: ${e.message}")
                }
            }
        }

        executor.shutdown()
        executor.awaitTermination(30, TimeUnit.MINUTES)
        initScript.delete()

        val lockCount = outDir.walkTopDown().filter { it.name == "gradle.lockfile" }.count()
        logger.lifecycle("Generated $lockCount lock files in $outDir")
    }
}
