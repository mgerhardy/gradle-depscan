package io.github.mgerhardy.depscan

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import java.io.File
import java.net.HttpURLConnection
import java.net.URI

@DisableCachingByDefault(because = "Uses persistent install directory with manual up-to-date check")
abstract class DepscanDownloadTask : DefaultTask() {
    @get:Input
    abstract val version: Property<String>

    @get:Optional
    @get:Input
    abstract val downloadUrl: Property<String>

    @get:OutputDirectory
    abstract val installDir: DirectoryProperty

    @TaskAction
    fun download() {
        val ver = version.get()
        val dir = installDir.get().asFile
        val binary = File(dir, binaryName())

        if (binary.exists()) {
            logger.lifecycle("depscan $ver already present at ${binary.absolutePath}")
            return
        }

        dir.mkdirs()
        val os = detectOs()
        val arch = detectArch()
        val asset = "depscan-${os}-${arch}"
        val url = if (downloadUrl.isPresent) {
            val custom = downloadUrl.get()
            if (custom.endsWith(asset) || custom.endsWith(".exe")) custom
            else "${custom.trimEnd('/')}/$asset"
        } else {
            "https://github.com/owasp-dep-scan/dep-scan/releases/download/v${ver}/${asset}"
        }

        logger.lifecycle("Downloading depscan $ver from $url")
        downloadWithRetry(url, binary, maxRetries = 3)
        if (!isWindows()) binary.setExecutable(true)
        logger.lifecycle("depscan installed to ${binary.absolutePath}")
    }

    private fun downloadWithRetry(url: String, dest: File, maxRetries: Int) {
        var lastException: Exception? = null
        repeat(maxRetries) { attempt ->
            try {
                downloadFollowingRedirects(url, dest)
                return
            } catch (e: Exception) {
                lastException = e
                if (attempt < maxRetries - 1) {
                    val delay = (attempt + 1) * 2000L
                    logger.warn("Download attempt ${attempt + 1} failed: ${e.message}. Retrying in ${delay}ms...")
                    Thread.sleep(delay)
                    dest.delete()
                }
            }
        }
        throw lastException!!
    }

    private fun downloadFollowingRedirects(url: String, dest: File, maxRedirects: Int = 5) {
        var currentUrl = url
        repeat(maxRedirects) {
            val conn = URI(currentUrl).toURL().openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 30000
            conn.readTimeout = 60000
            conn.connect()
            val code = conn.responseCode
            if (code in 301..308) {
                currentUrl = conn.getHeaderField("Location") ?: error("Redirect without Location header")
                conn.disconnect()
                return@repeat
            }
            if (code != 200) {
                conn.disconnect()
                error("Download failed with HTTP $code for $currentUrl")
            }
            conn.inputStream.use { input -> dest.outputStream().use { input.copyTo(it) } }
            conn.disconnect()
            return
        }
        error("Too many redirects downloading $url")
    }

    companion object {
        fun isWindows(): Boolean = System.getProperty("os.name").lowercase().contains("windows")

        fun detectOs(): String {
            val name = System.getProperty("os.name").lowercase()
            return when {
                name.contains("linux") -> "linux"
                name.contains("mac") || name.contains("darwin") -> "darwin"
                name.contains("windows") -> "windows"
                else -> error("Unsupported OS: $name")
            }
        }

        fun detectArch(): String {
            val arch = System.getProperty("os.arch").lowercase()
            return when {
                arch.contains("aarch64") || arch.contains("arm64") -> "arm64"
                arch.contains("amd64") || arch.contains("x86_64") -> "amd64"
                else -> error("Unsupported architecture: $arch")
            }
        }

        fun binaryName(): String {
            val os = detectOs()
            val arch = detectArch()
            return if (isWindows()) "depscan-${os}-${arch}.exe" else "depscan-${os}-${arch}"
        }
    }
}
