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

        val isCompositeBuild = project.gradle.includedBuilds.isNotEmpty()

        // Discover Java subprojects (lazily)
        val javaSubprojects = project.provider {
            val excludes = extension.excludeProjects.get().toSet()
            project.subprojects.filter { sub ->
                sub.plugins.hasPlugin("java") && sub.name !in excludes && sub.path !in excludes
            }.toList()
        }

        // Collect artifact directories -- supports both regular and composite builds
        val artifactDirs = if (isCompositeBuild) {
            project.provider {
                val excludes = extension.excludeProjects.get().toSet()
                discoverCompositeBuildArtifactDirs(project, excludes)
            }
        } else {
            javaSubprojects.map { subs ->
                subs.map { sub ->
                    File(sub.layout.buildDirectory.get().asFile, "libs").absolutePath
                }
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
            // Only set javaProjects for non-composite builds (composite uses file-based resolution)
            if (!isCompositeBuild) {
                it.javaProjects.set(javaSubprojects)
            }
        }

        project.tasks.register("depscanFullScan") {
            it.group = "depscan"
            it.description = "Runs the complete depscan analysis pipeline"
            it.dependsOn(reachabilityTask)
        }

        // Wire assemble dependencies
        if (isCompositeBuild) {
            // Composite build: no task dependency on included builds' assemble.
            // Gradle does not support dependsOn or shouldRunAfter across the
            // composite boundary. The scan tasks simply scan whatever artifacts
            // are already built on disk. In CI, assemble runs before depscan
            // as a separate Gradle invocation.
            project.logger.info("Depscan: composite build detected -- scan will use pre-built artifacts")
        } else {
            // Regular build: depend on subproject assemble tasks
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

    companion object {
        /**
         * Discovers build/libs directories across all included builds in a composite.
         *
         * Walks each included build's project directory looking for build/libs/ directories
         * that contain scannable artifacts (boot WARs, JARs).
         */
        fun discoverCompositeBuildArtifactDirs(project: Project, excludes: Set<String>): List<String> {
            val dirs = mutableListOf<String>()
            for (included in project.gradle.includedBuilds) {
                if (included.name in excludes) continue
                val buildRoot = included.projectDir
                // Walk the included build looking for build/libs directories with artifacts
                buildRoot.walkTopDown()
                    .maxDepth(6)
                    .filter { it.isDirectory && it.name == "libs" && it.parentFile.name == "build" }
                    .filter { libsDir ->
                        // Only include if it actually has scannable artifacts
                        DepscanScanTask.pickArtifact(libsDir) != null
                    }
                    .forEach { libsDir ->
                        val subprojectName = libsDir.parentFile.parentFile?.name ?: included.name
                        if (subprojectName !in excludes) {
                            dirs.add(libsDir.absolutePath)
                        }
                    }
            }
            project.logger.lifecycle("Composite build: discovered ${dirs.size} artifact directories across ${project.gradle.includedBuilds.size} included builds")
            return dirs
        }
    }
}
