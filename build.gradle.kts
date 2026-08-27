plugins {
    `java-gradle-plugin`
    `maven-publish`
    kotlin("jvm") version "2.3.20"
    id("com.gradle.plugin-publish") version "1.3.1"
}

group = "io.github.mgerhardy"
version = findProperty("version") as String? ?: "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(gradleApi())
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

testing {
    suites {
        val functionalTest by registering(JvmTestSuite::class) {
            useKotlinTest()
            dependencies {
                implementation(project())
            }
            gradlePlugin.testSourceSets.add(sources)
        }
    }
}

tasks.check { dependsOn(testing.suites.named("functionalTest")) }

gradlePlugin {
    website = "https://github.com/mgerhardy/gradle-depscan"
    vcsUrl = "https://github.com/mgerhardy/gradle-depscan"
    plugins {
        create("depscan") {
            id = "io.github.mgerhardy.depscan"
            implementationClass = "io.github.mgerhardy.depscan.DepscanPlugin"
            displayName = "Gradle Depscan Plugin"
            description = "Wraps OWASP dep-scan for vulnerability scanning with reachability analysis"
            tags = listOf("security", "depscan", "vulnerability", "reachability", "csaf", "vex")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
