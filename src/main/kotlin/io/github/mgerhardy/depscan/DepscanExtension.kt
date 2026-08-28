package io.github.mgerhardy.depscan

import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

abstract class DepscanExtension {
    // Core
    abstract val version: Property<String>
    abstract val installDir: DirectoryProperty
    abstract val binaryPath: RegularFileProperty
    abstract val downloadUrl: Property<String>

    // Scanning
    abstract val targetType: Property<String>
    abstract val profile: Property<String>
    abstract val reachabilityAnalyzer: Property<String>
    abstract val vdbScope: Property<String>
    abstract val includeTestDependencies: Property<Boolean>
    abstract val additionalScanArgs: ListProperty<String>
    abstract val additionalReachabilityArgs: ListProperty<String>

    // Output
    abstract val reportsDir: DirectoryProperty

    // Caching
    abstract val vdbHome: DirectoryProperty

    // Project filtering
    abstract val excludeProjects: ListProperty<String>

    // Lock file generation
    abstract val maxParallelLocks: Property<Int>
    abstract val perProjectTimeoutSeconds: Property<Long>

    init {
        version.convention("6.3.0")
        targetType.convention("java")
        profile.convention("research")
        reachabilityAnalyzer.convention("SemanticReachability")
        vdbScope.convention("app")
        includeTestDependencies.convention(false)
        additionalScanArgs.convention(emptyList())
        additionalReachabilityArgs.convention(emptyList())
        excludeProjects.convention(emptyList())
        maxParallelLocks.convention(4)
        perProjectTimeoutSeconds.convention(300L)
    }
}
