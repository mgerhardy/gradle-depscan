package io.github.mgerhardy.depscan

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DepscanPluginFunctionalTest {

    @Test
    fun `plugin applies and registers tasks`() {
        val projectDir = createTempProject()
        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("tasks", "--group=depscan")
            .build()

        assertTrue(result.output.contains("depscanDownload"))
        assertTrue(result.output.contains("depscanLockGradle"))
        assertTrue(result.output.contains("depscanScan"))
        assertTrue(result.output.contains("depscanReachability"))
        assertTrue(result.output.contains("depscanFullScan"))
    }

    @Test
    fun `depscanDownload is skipped when binaryPath is set`() {
        val projectDir = createTempProject("""
            depscan {
                binaryPath.set(file("fake-depscan"))
            }
        """.trimIndent())
        File(projectDir, "fake-depscan").apply { writeText("#!/bin/sh"); setExecutable(true) }

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("depscanDownload")
            .build()

        assertEquals(TaskOutcome.SKIPPED, result.task(":depscanDownload")?.outcome)
    }

    @Test
    fun `extension defaults are applied`() {
        val projectDir = createTempProject("""
            tasks.register("printDefaults") {
                doLast {
                    val ext = project.extensions.getByType(io.github.mgerhardy.depscan.DepscanExtension::class.java)
                    println("version=" + ext.version.get())
                    println("targetType=" + ext.targetType.get())
                    println("profile=" + ext.profile.get())
                    println("reachabilityAnalyzer=" + ext.reachabilityAnalyzer.get())
                    println("vdbScope=" + ext.vdbScope.get())
                    println("includeTestDependencies=" + ext.includeTestDependencies.get())
                }
            }
        """.trimIndent())

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("printDefaults")
            .build()

        assertTrue(result.output.contains("version=6.3.0"))
        assertTrue(result.output.contains("targetType=java"))
        assertTrue(result.output.contains("profile=research"))
        assertTrue(result.output.contains("reachabilityAnalyzer=SemanticReachability"))
        assertTrue(result.output.contains("vdbScope=app"))
        assertTrue(result.output.contains("includeTestDependencies=false"))
    }

    @Test
    fun `extension values are configurable`() {
        val projectDir = createTempProject("""
            depscan {
                version.set("7.0.0")
                includeTestDependencies.set(true)
                excludeProjects.set(listOf("test-utils"))
            }
            tasks.register("printConfig") {
                doLast {
                    val ext = project.extensions.getByType(io.github.mgerhardy.depscan.DepscanExtension::class.java)
                    println("version=" + ext.version.get())
                    println("includeTestDependencies=" + ext.includeTestDependencies.get())
                    println("excludeProjects=" + ext.excludeProjects.get())
                }
            }
        """.trimIndent())

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("printConfig")
            .build()

        assertTrue(result.output.contains("version=7.0.0"))
        assertTrue(result.output.contains("includeTestDependencies=true"))
        assertTrue(result.output.contains("excludeProjects=[test-utils]"))
    }

    @Test
    fun `depscanFullScan depends on depscanReachability`() {
        val projectDir = createTempProject()
        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("depscanFullScan", "--dry-run")
            .build()

        assertTrue(result.output.contains(":depscanReachability"))
        assertTrue(result.output.contains(":depscanFullScan"))
    }

    @Test
    fun `depscanLockGradle generates lock files for java project`() {
        // Create a separate target project that the lock task will scan
        // This project only needs standard plugins - no depscan plugin
        val targetDir = File.createTempFile("depscan-target", "").apply { delete(); mkdirs() }
        targetDir.deleteOnExit()
        File(targetDir, "settings.gradle").writeText("rootProject.name = 'target-project'")
        File(targetDir, "build.gradle").writeText("""
            plugins { id 'java' }
            repositories { mavenCentral() }
            dependencies { implementation 'com.google.guava:guava:33.4.8-jre' }
        """.trimIndent())
        // Provision gradle wrapper
        val ownWrapper = File(System.getProperty("user.dir"), "gradle/wrapper")
        val targetWrapper = File(targetDir, "gradle/wrapper")
        targetWrapper.mkdirs()
        File(ownWrapper, "gradle-wrapper.jar").copyTo(File(targetWrapper, "gradle-wrapper.jar"))
        File(ownWrapper, "gradle-wrapper.properties").copyTo(File(targetWrapper, "gradle-wrapper.properties"))
        File(System.getProperty("user.dir"), "gradlew").copyTo(File(targetDir, "gradlew")).setExecutable(true)

        // Create the depscan plugin project that points scanTarget at the target
        val projectDir = createTempProject("""
            depscan {
                // not needed but avoids warnings
            }
            tasks.named<io.github.mgerhardy.depscan.DepscanLockGradleTask>("depscanLockGradle") {
                scanTarget.set(file("${targetDir.absolutePath.replace("\\", "\\\\")}"))
            }
        """.trimIndent())

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("depscanLockGradle", "--stacktrace")
            .build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":depscanLockGradle")?.outcome)
        val lockDir = File(projectDir, "build/depscan-locks/gradle")
        assertTrue(lockDir.exists(), "Lock directory should exist")
        val lockFiles = lockDir.walkTopDown().filter { it.name == "gradle.lockfile" }.toList()
        assertTrue(lockFiles.isNotEmpty(), "At least one lock file should be generated: ${result.output}")
        val content = lockFiles.first().readText()
        assertTrue(content.contains("com.google.guava:guava"), "Lock file should contain guava dependency")
    }

    @Test
    fun `depscanReachability depends on depscanLockGradle`() {
        val projectDir = createTempProject()
        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("depscanReachability", "--dry-run")
            .build()

        assertTrue(result.output.contains(":depscanLockGradle"))
        assertTrue(result.output.contains(":depscanReachability"))
    }

    private fun createTempProject(extraConfig: String = ""): File {
        val dir = File.createTempFile("depscan-test", "").apply { delete(); mkdirs() }
        dir.deleteOnExit()
        File(dir, "settings.gradle.kts").writeText("rootProject.name = \"test-project\"")
        File(dir, "build.gradle.kts").writeText("""
            plugins {
                id("io.github.mgerhardy.depscan")
            }
            $extraConfig
        """.trimIndent())
        return dir
    }
}
