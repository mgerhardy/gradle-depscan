package io.github.mgerhardy.depscan

import org.gradle.api.Project
import org.gradle.api.logging.Logger

/**
 * Resolves runtime dependency coordinates (group:name) from Java subprojects.
 * Used to identify test-only dependencies for CSAF report filtering.
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
