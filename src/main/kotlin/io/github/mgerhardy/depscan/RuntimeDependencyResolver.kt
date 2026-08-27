package io.github.mgerhardy.depscan

import org.gradle.api.Project
import org.gradle.api.logging.Logger
import java.io.File

/**
 * Resolves runtime dependency coordinates (group:name) from Java subprojects.
 * Used to identify test-only dependencies for CSAF report filtering.
 *
 * Supports two modes:
 * 1. Direct resolution via Project objects (regular multi-project builds)
 * 2. File-based resolution by scanning build directories (composite builds)
 */
object RuntimeDependencyResolver {

    /**
     * Collects the union of all runtime dependency coordinates across the given projects.
     * Returns a set of "group:name" strings (version stripped for matching against CVE reports).
     */
    fun collectRuntimeDeps(projects: List<Project>, logger: Logger): Set<String> {
        val allDeps = mutableSetOf<String>()
        for (project in projects) {
            val deps = resolveForProject(project, logger)
            allDeps.addAll(deps)
        }
        logger.lifecycle("Collected ${allDeps.size} unique runtime dependencies from ${projects.size} projects")
        return allDeps
    }

    /**
     * Collects runtime dependencies by scanning artifact directories for co-located
     * runtime-deps.txt files. Used for composite builds where Project objects are
     * not accessible across the included-build boundary.
     *
     * The plugin generates runtime-deps.txt files alongside build/libs/ via the
     * exportRuntimeDeps task. Each line is a group:name:version coordinate.
     */
    fun collectRuntimeDepsFromFiles(artifactDirs: List<String>, logger: Logger): Set<String> {
        val allDeps = mutableSetOf<String>()
        var fileCount = 0
        for (dir in artifactDirs) {
            // runtime-deps.txt lives in the build/ directory, sibling to libs/
            val libsDir = File(dir)
            val buildDir = libsDir.parentFile ?: continue
            val depsFile = File(buildDir, "runtime-deps.txt")
            if (!depsFile.exists()) {
                // Also check in the subproject that owns this build dir
                val projectDir = buildDir.parentFile ?: continue
                val altDepsFile = File(projectDir, "build/runtime-deps.txt")
                if (!altDepsFile.exists()) continue
                fileCount++
                parseDepsFile(altDepsFile, allDeps)
                continue
            }
            fileCount++
            parseDepsFile(depsFile, allDeps)
        }
        if (fileCount > 0) {
            logger.lifecycle("Collected ${allDeps.size} unique runtime dependencies from $fileCount runtime-deps.txt files")
        } else {
            logger.lifecycle("No runtime-deps.txt files found; test-scope filtering will be skipped")
        }
        return allDeps
    }

    private fun parseDepsFile(file: File, target: MutableSet<String>) {
        for (line in file.readLines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(":")
            if (parts.size >= 2) {
                target.add("${parts[0]}:${parts[1]}")
            }
        }
    }

    /**
     * Resolves runtimeClasspath for a single project and returns group:name coordinates.
     */
    private fun resolveForProject(project: Project, logger: Logger): Set<String> {
        val config = project.configurations.findByName("runtimeClasspath") ?: return emptySet()
        return try {
            config.resolvedConfiguration.resolvedArtifacts.map { artifact ->
                val id = artifact.moduleVersion.id
                "${id.group}:${id.name}"
            }.toSet()
        } catch (e: Exception) {
            logger.warn("Failed to resolve runtimeClasspath for ${project.path}: ${e.message}")
            emptySet()
        }
    }
}
