package dev.rourunisen.tapauth.network

import dev.rourunisen.tapauth.crypto.ParsedPairingProvision
import java.util.Arrays
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The carrier of the decrypted provision payload: it must not print the CSK, and its transient
 * bytes must not be the ones the device record keeps.
 *
 * The generated UniFFI record `ParsedPairingProvision` has no redacting `toString()` and cannot be
 * given one — Rust's hand-written `Debug` redacts the CSK on its side of the boundary and the
 * compiler derives the Kotlin one — so [PairingProvision] is the only form of it Kotlin passes on.
 * Likewise, the record's `csk` `ByteArray` is the *transient*: the device record has to outlive it,
 * so it gets a copy, and this test pins that the two are different objects — the property that
 * makes clearing the transient safe (`assurance-strategy.md` §6, third row).
 */
class PairingProvisionTest {

    private companion object {
        /** A CSK with no repeated byte, so each of its rendered forms is distinctive. */
        val CSK = ByteArray(32) { (it * 7 + 3).toByte() }
    }

    /** The decrypted payload as Rust hands it over: it owns [CSK]'s bytes. */
    private fun record() =
        ParsedPairingProvision(csk = CSK.copyOf(), username = "alice", clientHostname = "laptop")

    /**
     * The defect this catches: a `toString()` that renders the CSK in any of the forms a key is
     * printed in — the `Arrays.toString` form a derived `toString()` would use, hex, or base64. The
     * carrier is the one object the payload is allowed to live in, so a leak here is the leak the
     * whole redaction exists to prevent.
     */
    @Test
    fun theProvisionIsNeverRenderedWithItsKey() {
        val rendered = PairingProvision.from(record()).toString()

        assertFalse(
            "the derived Arrays.toString form: $rendered",
            rendered.contains(Arrays.toString(CSK)),
        )
        assertFalse("hex form: $rendered", rendered.contains(CSK.toHex()))
        assertFalse(
            "base64 form: $rendered",
            rendered.contains(Base64.getEncoder().encodeToString(CSK)),
        )
        assertTrue(
            "the username is what makes the line useful: $rendered",
            rendered.contains("alice"),
        )
        assertTrue(
            "the hostname is what makes the line useful: $rendered",
            rendered.contains("laptop"),
        )
        assertTrue(
            "the rendering has to say the key was withheld: $rendered",
            rendered.contains("csk=<redacted>"),
        )
    }

    /**
     * The ownership property the clearing rests on: the durable copy is a different array from the
     * transient, so zeroizing the transient leaves the record's key intact.
     *
     * The defect this catches: `copyCsk()` returning the transient itself (a hand-off by reference,
     * which is what the code did before this change — `PairedDevice(csk = provision.csk)` — and
     * what makes a clear beside the save zeroize the key every later authentication reads).
     */
    @Test
    fun theDurableCopyIsNotTheTransientAndSurvivesItsClearing() {
        val record = record()
        val provision = PairingProvision.from(record)

        val durable = provision.copyCsk()
        assertNotSame("the copy must be a different array than the transient", record.csk, durable)
        assertArrayEquals("the copy must carry the key", CSK, durable)

        provision.zeroize()

        assertArrayEquals("clearing the transient must not touch the durable copy", CSK, durable)
        assertArrayEquals(
            "the transient handed over by Rust must really be cleared",
            ByteArray(CSK.size),
            record.csk,
        )
    }

    /**
     * Copying after the transient was cleared is refused instead of returning zeros: a zero CSK
     * persisted into a `PairedDevice` is a pairing that can never authenticate, and it would be
     * discovered only at the next login attempt.
     *
     * The defect this catches: a `zeroize()` that only fills the array in place, so a later copy
     * silently yields 32 zero bytes, or an ordering bug that persists after clearing.
     */
    @Test
    fun aClearedTransientCannotBeCopiedAgain() {
        val provision = PairingProvision.from(record())
        provision.zeroize()

        assertThrows(IllegalStateException::class.java) { provision.copyCsk() }
    }

    /**
     * The peer-supplied fields are scrubbed, because this rendering exists to be logged.
     *
     * A provision comes from the desktop, so `username` and `clientHostname` are whatever that side
     * sent — including a newline that forges a second log entry and an ANSI escape that rewrites
     * the line the operator is reading. [scrubLogValue] is the same filter the session's own log
     * lines apply, and this pins that the one string built for a log line uses it.
     *
     * The defect this catches: rendering the fields verbatim (what this `toString` did before),
     * which hands a hostile desktop control of the log text.
     */
    @Test
    fun theRenderedFieldsAreScrubbedOfLogControlCharacters() {
        val hostile =
            ParsedPairingProvision(
                csk = CSK.copyOf(),
                username = "alice\n2026-01-01 Paired 'admin'",
                clientHostname = "laptop\u001B[2Kspoofed",
            )

        val rendered = PairingProvision.from(hostile).toString()

        assertFalse("a newline must not survive: $rendered", rendered.contains('\n'))
        assertFalse("an escape must not survive: $rendered", rendered.contains('\u001B'))
        assertTrue(
            "the visible characters must still be there: $rendered",
            rendered.contains("alice"),
        )
        assertFalse("the CSK must still be redacted: $rendered", rendered.contains(CSK.toHex()))
    }

    /** Zeroizing twice is the normal case: every exit path of the confirmation asks for it. */
    @Test
    fun zeroizingIsIdempotent() {
        val record = record()
        val provision = PairingProvision.from(record)
        provision.zeroize()
        provision.zeroize()

        assertArrayEquals(ByteArray(CSK.size), record.csk)
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { ((it.toInt() and 0xff) + 0x100).toString(16).substring(1) }
}
