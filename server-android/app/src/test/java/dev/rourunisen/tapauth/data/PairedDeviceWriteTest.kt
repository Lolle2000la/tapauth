package dev.rourunisen.tapauth.data

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The durable-write decision of the paired-device list.
 *
 * `SharedPreferences.commit()` answers *whether* the write reached the disk, and
 * `DeviceRepository.savePairedDevice` used to drop that answer: a rejected commit left no device
 * row while the pairing went on to tell the desktop it had succeeded, so the desktop held a pairing
 * the phone did not and every later authentication failed. The commit is a `(String) -> Boolean`
 * here rather than a `SharedPreferences` call so this decision — not the JSON encoding, which the
 * JVM unit tests cannot run — can be exercised by the test that would have caught it.
 *
 * The `(String) -> Boolean` is also what makes `apply()` unusable at the call site: it returns
 * nothing, so it cannot produce the value this class is given.
 */
class PairedDeviceWriteTest {

    /**
     * The defect this catches: a persist path that treats a rejected write as success — the state
     * the phone was in before this change, where `commit()`'s result was discarded and the pairing
     * announced itself with no device on disk. `false` here is exactly what `commit()` returns when
     * `SharedPreferences` could not write.
     */
    @Test
    fun aRejectedCommitIsAnErrorRatherThanASilentSuccess() {
        val write = PairedDeviceWrite { false }

        val thrown =
            assertThrows(IOException::class.java) { write.write("""[{"deviceId":"aa11"}]""") }

        assertEquals(
            "The message is what the pairing screen renders, so it has to say what happened",
            PairedDeviceWrite.UNSAVED_MESSAGE,
            thrown.message,
        )
    }

    /**
     * A commit that succeeded is not an error, and the caller carries on to notify its observers.
     */
    @Test
    fun anAcceptedCommitIsNotAnError() {
        val written = mutableListOf<String>()
        val write = PairedDeviceWrite { json ->
            written += json
            true
        }

        write.write("""[{"deviceId":"aa11"}]""")

        assertEquals(
            "The serialized list must reach the commit, unchanged",
            listOf("""[{"deviceId":"aa11"}]"""),
            written,
        )
    }
}
