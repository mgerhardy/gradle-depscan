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
        // (used as fallback when lock files are not available)
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

        // Lock file output directory
        val lockOutputDir = project.layout.buildDirectory.dir("depscan-locks/gradle")

        // Determine scan target for lock file generation
        val scanTargetDir = if (isCompositeBuild) {
            // For composite builds, scan from the project directory
            project.layout.projectDirectory
        } else {
            project.layout.projectDirectory
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

        // Lock file generation task (no compilation needed)
        val lockTask = project.tasks.register("depscanLockGradle", DepscanLockGradleTask::class.java) {
            it.group = "depscan"
            it.description = "Generates Gradle dependency lock files for vulnerability scanning (no compilation needed)"
            it.scanTarget.set(scanTargetDir)
            it.outputDir.set(lockOutputDir)
            it.maxParallelLocks.set(extension.maxParallelLocks)
            it.excludeProjects.set(extension.excludeProjects)
            it.perProjectTimeoutSeconds.set(extension.perProjectTimeoutSeconds)
            // Narrowed inputs: only build script files
            it.buildScriptFiles.from(
                project.provider {
                    project.fileTree(scanTargetDir) { tree ->
                        tree.include(
                            "**/settings.gradle", "**/settings.gradle.kts",
                            "**/build.gradle", "**/build.gradle.kts",
                            "**/gradle.properties", "**/libs.versions.toml"
                        )
                        tree.exclude(
                            "**/node_modules/**", "**/build/**",
                            "**/.git/**", "**/.gradle/**"
                        )
                    }
                }
            )
        }

        val scanTask = project.tasks.register("depscanScan", DepscanScanTask::class.java) {
            it.group = "depscan"
            it.description = "Runs depscan vulnerability scan"
            it.dependsOn(downloadTask, lockTask)
            it.depscanBinary.set(effectiveBinary)
            it.targetType.set(extension.targetType)
            it.vdbScope.set(extension.vdbScope)
            it.additionalArgs.set(extension.additionalScanArgs)
            it.reportsDir.set(extension.reportsDir)
            it.vdbHome.set(extension.vdbHome.map { it.asFile.absolutePath })
            it.artifactDirs.set(artifactDirs)
            it.lockFilesDir.set(lockOutputDir.map { it.asFile.absolutePath })
        }

        val reachabilityTask = project.tasks.register("depscanReachability", DepscanReachabilityTask::class.java) {
            it.group = "depscan"
            it.description = "Runs depscan reachability analysis"
            it.dependsOn(downloadTask, lockTask)
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
            it.lockFilesDir.set(lockOutputDir.map { it.asFile.absolutePath })
            // Only set javaProjects for non-composite builds
            if (!isCompositeBuild) {
                it.javaProjects.set(javaSubprojects)
            }
        }

        project.tasks.register("depscanFullScan") {
            it.group = "depscan"
            it.description = "Runs the complete depscan analysis pipeline"
            it.dependsOn(reachabilityTask)
        }

        // For non-composite builds without lock files, fall back to assemble
        if (!isCompositeBuild) {
            project.afterEvaluate {
                val assembleTasks = javaSubprojects.get().mapNotNull { sub ->
                    sub.tasks.findByName("assemble")
                }
                if (assembleTasks.isNotEmpty()) {
                    // assemble is only needed if lock task is skipped
                    // The scan tasks prefer lock files when available
                    scanTask.configure { task ->
                        task.mustRunAfter(assembleTasks)
                    }
                    reachabilityTask.configure { task ->
                        task.mustRunAfter(assembleTasks)
                    }
                }
            }
        }
    }

    companion object {
        /**
         * Discovers build/libs directories across all included builds in a composite.
         * Used as fallback when lock files are not available.
         */
        fun discoverCompositeBuildArtifactDirs(project: Project, excludes: Set<String>): List<String> {
            val dirs = mutableListOf<String>()
            for (included in project.gradle.includedBuilds) {
                if (included.name in excludes) continue
                val buildRoot = included.projectDir
                buildRoot.walkTopDown()
                    .maxDepth(6)
                    .filter { it.isDirectory && it.name == "libs" && it.parentFile.name == "build" }
                    .filter { libsDir ->
                        DepscanScanTask.pickArtifact(libsDir) != null
                    }
                    .forEach { libsDir ->
                        val subprojectName = libsDir.parentFile.parentFile?.name ?: included.name
                        if (subprojectName !in excludes) {
                            dirs.add(libsDir.absolutePath)
                        }
                    }
            }
            project.logger.lifecycle(
                "Composite build: discovered ${dirs.size} artifact directories " +
                    "across ${project.gradle.includedBuilds.size} included builds"
            )
            return dirs
        }
    }
}
