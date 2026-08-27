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
