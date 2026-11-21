package dev.rourunisen.tapauth.service

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every caller-supplied string that reaches a `Log.*` call goes through [scrubLogValue].
 *
 * The values the desktop sends — the request's `username` and `hostname`, its `pam_service`,
 * `process_name` and `command_preview`, and the `allowedUsers`/`deviceName` a pairing persisted
 * from the peer's own `username`/`client_hostname` — are strings an unprivileged local user
 * controls. Interpolated raw into logcat, a newline in one forges an extra logcat line and an ANSI
 * escape rewrites the terminal of whoever reads the buffer, which is why the scrubbing exists.
 *
 * That property is a property of individual `Log.d`/`Log.w` arguments, which no JVM test can read
 * back — the call sites need a framework `BluetoothGatt`, a `Context` or a live socket to execute.
 * So this is a source-text guard, in the spirit of `client-pam/src/source_guards.rs`: it parses the
 * shipped call sites and fails when one of those values is interpolated without a scrubbing
 * wrapper. It does not replace the instrumentation suite; it is the only executable statement of
 * the rule that a unit test can make.
 *
 * Adding a new log line that carries one of these values therefore means wrapping it in
 * [scrubLogValue] (or `callerContextLogLine`, which scrubs its own arguments).
 */
class CallerLogScrubGuardTest {

    @Test
    fun noLogCallInterpolatesACallerSuppliedValueRaw() {
        val violations =
            productionSources().flatMap { file ->
                val text = file.readText()
                logCalls(text, file.path).flatMap { call ->
                    unwrappedCallerValues(call.text).map { "$it at ${call.path}:${call.line}" }
                }
            }

        assertEquals(
            "a caller-supplied value reaches logcat unwrapped: a newline in it forges an extra " +
                "logcat line and an escape sequence rewrites the reader's terminal. Wrap each in " +
                "scrubLogValue(...) — a value already logged elsewhere may be dropped instead.",
            emptyList<String>(),
            violations,
        )
    }

    /**
     * The detector works in both directions, so an edit that quietly disables it cannot leave the
     * guard above green: a raw interpolation has to be reported, a wrapped one and a word that
     * merely appears in the message text must not be.
     */
    @Test
    fun theDetectorReportsARawInterpolationAndAcceptsAScrubbedOne() {
        val fixture =
            listOf(
                    "Log.d(TAG, \"raw: \${authRequest.username}\")",
                    "Log.d(TAG, \"scrubbed: \${scrubLogValue(authRequest.hostname)}\")",
                    "Log.d(TAG, \"\${scrubLogValue(allowedUsers.joinToString())}\")",
                    "Log.d(TAG, \"no caller value in this message about username\")",
                    "Log.d(TAG, \"plain: \$hostname\")",
                    // Comments are not log text: a mention in one is not an interpolation.
                    "// Log.d(TAG, \"\${authRequest.username}\")",
                )
                .joinToString("\n")

        val calls = logCalls(fixture, "fixture.kt")

        assertEquals("comments must not be scanned as log calls", 5, calls.size)
        assertEquals(
            listOf("username"),
            unwrappedCallerValues(calls[0].text),
        )
        assertEquals(emptyList<String>(), unwrappedCallerValues(calls[1].text))
        assertEquals(emptyList<String>(), unwrappedCallerValues(calls[2].text))
        assertEquals(emptyList<String>(), unwrappedCallerValues(calls[3].text))
        assertEquals(listOf("hostname"), unwrappedCallerValues(calls[4].text))
    }

    /**
     * The scan reaches the call sites it is meant to guard.
     *
     * A guard that walks an empty file list — a moved source root, a changed working directory —
     * would pass [noLogCallInterpolatesACallerSuppliedValueRaw] without looking at anything, so the
     * two known caller-value lines are asserted to be *seen* here, and the file count is pinned.
     */
    @Test
    fun theScanReachesTheCallSitesItGuards() {
        val sources = productionSources()
        assertTrue(
            "the scan found only ${sources.size} Kotlin sources under $SOURCE_ROOT; it is not " +
                "looking at the app",
            sources.size >= 20,
        )

        val calls = sources.flatMap { logCalls(it.readText(), it.path) }
        val texts = calls.map { it.text }

        // The BLE receipt line (already scrubbed) and the caller-context line (whose builder
        // scrubs) are the two places these values reach logcat today, so both must be in the scan.
        assertTrue(
            "the receipt log line was not found by the scan; $SOURCE_ROOT may have moved",
            texts.any { it.contains("Parsed and verified BLE request") },
        )
        assertTrue(
            "the caller-context log call was not found by the scan",
            texts.any { it.contains("callerContextLogLine(") },
        )
    }

    /** One `Log.*(…)` call, with where it came from. */
    private class LogCall(val path: String, val line: Int, val text: String)

    /** The `Log.*(…)` calls in [source], with comments masked out and brackets balanced. */
    private fun logCalls(source: String, path: String): List<LogCall> {
        val masked = maskComments(source)
        val calls = mutableListOf<LogCall>()
        for (match in LOG_CALL.findAll(masked)) {
            val open = match.range.last
            val end = endOfCall(masked, open)
            val line = masked.lineNumberAt(match.range.first)
            calls += LogCall(path, line, masked.substring(match.range.first, end + 1))
        }
        return calls
    }

    /** Index of the `)` that closes the bracket at [open], or the last index of the text. */
    private fun endOfCall(text: String, open: Int): Int {
        var depth = 0
        var i = open
        var inString = false
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                when (c) {
                    '\\' -> i++ // skip the escaped character, so `\"` does not end the string
                    '"' -> inString = false
                }
            } else {
                when (c) {
                    '"' -> inString = true
                    '(' -> depth++
                    ')' -> {
                        depth--
                        if (depth == 0) return i
                    }
                }
            }
            i++
        }
        return text.length - 1
    }

    /**
     * The caller-supplied values interpolated into [text] that no scrubbing wrapper encloses.
     *
     * Both interpolation forms are covered (`$name` and `${expression}`), and the expression of a
     * `${…}` is analysed as code again — which is what lets `scrubLogValue(authRequest.username)`
     * pass while `authRequest.username` is reported.
     */
    private fun unwrappedCallerValues(text: String): List<String> {
        val found = mutableListOf<String>()
        val enclosing = ArrayDeque<String>()
        var lastWord = ""
        var inString = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                when {
                    c == '\\' -> i++
                    c == '"' -> inString = false
                    c == '$' && i + 1 < text.length && text[i + 1] == '{' -> {
                        val close = matchingBrace(text, i + 1)
                        found += unwrappedCallerValues(text.substring(i + 2, close))
                        i = close
                    }
                    c == '$' -> {
                        val name = identifierAt(text, i + 1)
                        if (name in CALLER_VALUES) found += name
                        i += name.length
                    }
                }
            } else {
                when {
                    c == '"' -> inString = true
                    c == '(' -> {
                        enclosing.addLast(lastWord)
                        lastWord = ""
                    }
                    c == ')' -> if (enclosing.isNotEmpty()) enclosing.removeLast()
                    c.isLetter() || c == '_' -> {
                        val name = identifierAt(text, i)
                        if (name in CALLER_VALUES && enclosing.none { it in SCRUBBING_WRAPPERS }) {
                            found += name
                        }
                        lastWord = name
                        i += name.length
                        continue
                    }
                }
                if (!c.isWhitespace()) lastWord = ""
            }
            i++
        }
        return found
    }

    /** Index of the `}` closing the `{` at [open], counting nested braces. */
    private fun matchingBrace(text: String, open: Int): Int {
        var depth = 0
        for (i in open until text.length) {
            when (text[i]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return i
                }
            }
        }
        return text.length - 1
    }

    /** The identifier starting at [start], or `""` when there is none. */
    private fun identifierAt(text: String, start: Int): String {
        var end = start
        while (end < text.length && (text[end].isLetterOrDigit() || text[end] == '_')) end++
        return text.substring(start, end)
    }

    /**
     * [source] with every comment replaced by spaces, newlines kept.
     *
     * A `Log.d` mentioned in a comment — the `scrubLogValue` rationale does exactly that — is prose
     * about logging, not a call site to guard, and a comment mentioning a caller field must not be
     * reported as an interpolation either.
     */
    private fun maskComments(source: String): String {
        val masked = StringBuilder(source)
        var inString = false
        var i = 0
        while (i < source.length) {
            val c = source[i]
            when {
                inString -> {
                    when (c) {
                        '\\' -> {
                            i++
                        }
                        '"' -> inString = false
                    }
                }
                c == '"' -> inString = true
                c == '/' && i + 1 < source.length && source[i + 1] == '/' -> {
                    while (i < source.length && source[i] != '\n') {
                        masked.setCharAt(i, ' ')
                        i++
                    }
                    continue
                }
                c == '/' && i + 1 < source.length && source[i + 1] == '*' -> {
                    while (
                        i < source.length &&
                            !(source[i] == '*' && i + 1 < source.length && source[i + 1] == '/')
                    ) {
                        if (source[i] != '\n') masked.setCharAt(i, ' ')
                        i++
                    }
                    // The closing `*/` itself, when the block is terminated.
                    if (i < source.length) masked.setCharAt(i, ' ')
                    i++
                    if (i < source.length) masked.setCharAt(i, ' ')
                }
            }
            i++
        }
        return masked.toString()
    }

    /** The line [index] falls on, 1-based. */
    private fun String.lineNumberAt(index: Int): Int {
        var line = 1
        for (i in 0 until minOf(index, length)) if (this[i] == '\n') line++
        return line
    }

    /** Every Kotlin source under the app's production tree. */
    private fun productionSources(): List<File> {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val root = File(directory, SOURCE_ROOT)
            if (root.isDirectory) {
                return root
                    .walkTopDown()
                    .filter { it.isFile && it.extension == "kt" }
                    .sorted()
                    .toList()
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "$SOURCE_ROOT was not found above ${File("").absolutePath}; the log call sites " +
                "cannot be guarded from this working directory",
        )
    }

    private companion object {
        const val SOURCE_ROOT = "app/src/main/java"

        /** `Log.d(`, `Log.i(`, `Log.w(`, `Log.e(`, `Log.v(` — qualified or not. */
        val LOG_CALL = Regex("\\bLog\\.[diwev]\\s*\\(")

        /** Field names whose values come from the desktop or from what it provisioned. */
        val CALLER_VALUES =
            setOf(
                "username",
                "hostname",
                "pamService",
                "processName",
                "commandPreview",
                "allowedUsers",
                "deviceName",
            )

        /** Functions whose arguments reach logcat already scrubbed. */
        val SCRUBBING_WRAPPERS = setOf("scrubLogValue", "callerContextLogLine")
    }
}
