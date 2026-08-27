package io.github.mgerhardy.depscan

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
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

@DisableCachingByDefault(because = "Scan results depend on external vulnerability database")
abstract class DepscanScanTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val depscanBinary: RegularFileProperty

    @get:Input
    abstract val targetType: Property<String>

    @get:Input
    abstract val vdbScope: Property<String>

    @get:Input
    abstract val additionalArgs: ListProperty<String>

    @get:OutputDirectory
    abstract val reportsDir: DirectoryProperty

    @get:Optional
    @get:Input
    abstract val vdbHome: Property<String>

    @get:Input
    abstract val artifactDirs: ListProperty<String>

    @TaskAction
    fun scan() {
        val binary = depscanBinary.get().asFile.absolutePath
        val reports = reportsDir.get().asFile
        reports.mkdirs()

        val artifacts = findArtifacts()
        if (artifacts.isEmpty()) {
            logger.warn("No scannable artifacts found in any subproject build/libs/ directory.")
            logger.warn("In a composite build, run: ./gradlew assemble depscanScan")
            return
        }

        val env = buildEnvironment()

        for ((projectName, artifactFile) in artifacts) {
            val projectReportsDir = File(reports, projectName)
            projectReportsDir.mkdirs()

            logger.lifecycle("Scanning $projectName: ${artifactFile.name}")
            val args = mutableListOf(
                binary,
                "-t", targetType.get(),
                "-i", artifactFile.absolutePath,
                "--reports-dir", projectReportsDir.absolutePath,
                "--vdb-scope", vdbScope.get(),
                "--no-banner",
                "--no-vuln-table"
            )
            args.addAll(additionalArgs.get())

            val result = execOps.exec { spec ->
                spec.commandLine(args)
                spec.environment(env)
                spec.isIgnoreExitValue = true
            }
            if (result.exitValue != 0) {
                logger.warn("depscan scan for $projectName exited with code ${result.exitValue}")
            }
        }
        logger.lifecycle("Scan reports written to ${reports.absolutePath}")
    }

    private fun findArtifacts(): List<Pair<String, File>> {
        val results = mutableListOf<Pair<String, File>>()
        for (dir in artifactDirs.get()) {
            val libsDir = File(dir)
            if (!libsDir.exists()) continue
            val projectName = libsDir.parentFile.parentFile?.name ?: libsDir.parentFile.name
            val artifact = pickArtifact(libsDir) ?: continue
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

    companion object {
        fun pickArtifact(libsDir: File): File? {
            val files = libsDir.listFiles() ?: return null
            val candidates = files.filter { f ->
                f.isFile && (f.extension == "war" || f.extension == "jar") &&
                    !f.name.endsWith("-sources.jar") &&
                    !f.name.endsWith("-javadoc.jar") &&
                    !f.name.endsWith("-plain.jar")
            }
            // Prefer boot WARs/JARs
            return candidates.firstOrNull { it.name.contains("-boot") || it.name.contains("-all") }
                ?: candidates.firstOrNull { it.extension == "war" }
                ?: candidates.firstOrNull()
        }
    }
}
