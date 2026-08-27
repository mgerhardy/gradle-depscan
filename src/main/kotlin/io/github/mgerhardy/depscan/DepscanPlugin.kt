package io.github.mgerhardy.depscan

import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

class DepscanPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create("depscan", DepscanExtension::class.java)

        // Default output directories
        extension.reportsDir.convention(project.layout.buildDirectory.dir("reports/depscan"))

        // Compute install and cache directories
        val gradleCaches = File(project.gradle.gradleUserHomeDir, "caches/depscan")
        val defaultInstallDir = project.layout.dir(
            extension.version.map { File(gradleCaches, "bin/$it") }
        )
        val defaultVdbHome = project.layout.dir(
            project.provider { File(gradleCaches, "vdb") }
        )
        extension.vdbHome.convention(defaultVdbHome)

        val effectiveInstallDir = extension.installDir.orElse(defaultInstallDir)
        val binaryFile = effectiveInstallDir.map { it.file(DepscanDownloadTask.binaryName()) }
        val effectiveBinary = extension.binaryPath.orElse(binaryFile)

        // Discover Java subprojects (lazily)
        val javaSubprojects = project.provider {
            val excludes = extension.excludeProjects.get().toSet()
            project.subprojects.filter { sub ->
                sub.plugins.hasPlugin("java") && sub.name !in excludes && sub.path !in excludes
            }.toList()
        }

        // Collect artifact directories from subprojects
        val artifactDirs = javaSubprojects.map { subs ->
            subs.map { sub ->
                File(sub.layout.buildDirectory.get().asFile, "libs").absolutePath
            }
        }

        // Register tasks
        val downloadTask = project.tasks.register("depscanDownload", DepscanDownloadTask::class.java) {
            it.group = "depscan"
            it.description = "Downloads the depscan binary"
            it.version.set(extension.version)
            it.downloadUrl.set(extension.downloadUrl)
            it.installDir.set(effectiveInstallDir)
            it.onlyIf { !extension.binaryPath.isPresent }
        }

        val scanTask = project.tasks.register("depscanScan", DepscanScanTask::class.java) {
            it.group = "depscan"
            it.description = "Runs depscan vulnerability scan on built artifacts"
            it.dependsOn(downloadTask)
            it.depscanBinary.set(effectiveBinary)
            it.targetType.set(extension.targetType)
            it.vdbScope.set(extension.vdbScope)
            it.additionalArgs.set(extension.additionalScanArgs)
            it.reportsDir.set(extension.reportsDir)
            it.vdbHome.set(extension.vdbHome.map { it.asFile.absolutePath })
            it.artifactDirs.set(artifactDirs)
        }

        val reachabilityTask = project.tasks.register("depscanReachability", DepscanReachabilityTask::class.java) {
            it.group = "depscan"
            it.description = "Runs depscan reachability analysis on built artifacts"
            it.dependsOn(downloadTask)
            it.depscanBinary.set(effectiveBinary)
            it.targetType.set(extension.targetType)
            it.profile.set(extension.profile)
            it.reachabilityAnalyzer.set(extension.reachabilityAnalyzer)
            it.vdbScope.set(extension.vdbScope)
            it.includeTestDependencies.set(extension.includeTestDependencies)
            it.additionalArgs.set(extension.additionalReachabilityArgs)
            it.reportsDir.set(extension.reportsDir)
            it.vdbHome.set(extension.vdbHome.map { it.asFile.absolutePath })
            it.artifactDirs.set(artifactDirs)
            it.javaProjects.set(javaSubprojects)
        }

        project.tasks.register("depscanFullScan") {
            it.group = "depscan"
            it.description = "Runs the complete depscan analysis pipeline"
            it.dependsOn(reachabilityTask)
        }

        // Wire assemble dependency after evaluation (subprojects may not have java plugin yet)
        project.afterEvaluate {
            val assembleTasks = javaSubprojects.get().mapNotNull { sub ->
                sub.tasks.findByName("assemble")
            }
            if (assembleTasks.isNotEmpty()) {
                scanTask.configure { task -> assembleTasks.forEach { task.dependsOn(it) } }
                reachabilityTask.configure { task -> assembleTasks.forEach { task.dependsOn(it) } }
            }
        }
    }
}
