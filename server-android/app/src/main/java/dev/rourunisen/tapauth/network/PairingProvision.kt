package dev.rourunisen.tapauth.network

import dev.rourunisen.tapauth.crypto.ParsedPairingProvision
import dev.rourunisen.tapauth.service.scrubLogValue

/**
 * The decrypted provisioning payload of `PairingConfirmClient`, in a shape Kotlin owns.
 *
 * ### Why this type exists at all
 *
 * The payload arrives as the generated UniFFI record [ParsedPairingProvision], and that record
 * cannot be made safe to print: its `toString()` is the Kotlin compiler's, which renders a
 * `ByteArray` field through `java.util.Arrays.toString`, so any log line carrying it prints
 * `csk=[12, 255, …]` — the key itself. Rust's hand-written `Debug` redacts the same fields on its
 * own side of the boundary (`shared/src/ffi.rs`) and cannot influence the generated Kotlin. There
 * is no override to add to a generated `data class`, so this type is the boundary instead: [from]
 * is the only place the record is read, it takes ownership of the CSK array, and the record is
 * dropped immediately — no field, parameter or local of this app holds it long enough to be logged.
 *
 * ### Who owns the CSK bytes
 *
 * The CSK has two lifetimes here and they are two different buffers. The one this object holds is
 * the **transient**: the `ByteArray` Rust allocated for the decrypted payload. Its last reader is
 * the device record, which needs its own copy because every later authentication reads it —
 * temporal identifiers, the BLE advertisement index, the AEAD — while the transient is dead the
 * moment that copy exists. So persisting takes [copyCsk] and then [zeroize]s the transient in a
 * `finally`, which is safe precisely because the copy is a different array: the live
 * [dev.rourunisen.tapauth.data.PairedDevice] keeps working and the transient is gone. The two
 * alternatives were rejected for that reason, not for taste: handing the transient to
 * `PairedDevice` **by reference** (the shape this replaced) makes clearing impossible, because a
 * `fill(0)` beside the save would zeroize the key the phone still needs for the next
 * authentication; and clearing only **on device removal** leaves the key in memory for the whole
 * life of the process, which is the interval this exists to bound. `assurance-strategy.md` §6
 * records that decision — do not "simplify" either back to it.
 */
internal class PairingProvision
private constructor(
    /** The Linux account the desktop provisioned. */
    val username: String,

    /** The desktop's authenticated hostname. */
    val clientHostname: String,

    /** The transient CSK: cleared by [zeroize], never handed out. */
    private var csk: ByteArray,
) {
    /** Whether [zeroize] has run. A later [copyCsk] is a caller-ordering bug, not a zero key. */
    private var cleared = false

    /**
     * A durable copy of the CSK, for the record that has to keep it.
     *
     * A copy and not the field: the caller owns what it gets back, so clearing the transient cannot
     * reach it, and the record outlives this object.
     *
     * @throws IllegalStateException when [zeroize] already ran — copying zeros into a
     *   `PairedDevice` would persist a key that can never authenticate
     */
    fun copyCsk(): ByteArray {
        check(!cleared) { "The provisioning CSK was already cleared" }
        return csk.copyOf()
    }

    /**
     * Clear the transient CSK bytes.
     *
     * Idempotent, and safe to call on every exit path (a refused commit, a failed send, a throw):
     * the bytes are the phone's own copy of a key Rust has already zeroized on its side.
     */
    fun zeroize() {
        if (cleared) return
        csk.fill(0)
        csk = ByteArray(0)
        cleared = true
    }

    /**
     * The non-secret fields only, scrubbed.
     *
     * The CSK is not rendered in any form — not the `Arrays.toString` form, not hex, not base64.
     * [username] and [clientHostname] are peer-supplied and this string exists to be logged, so
     * both go through [scrubLogValue]: a hostile desktop could otherwise put a newline or an ANSI
     * escape into the one string whose whole purpose is to reach a log line, and forge the next
     * entry.
     */
    override fun toString(): String =
        "PairingProvision(username=${scrubLogValue(username)}, " +
            "clientHostname=${scrubLogValue(clientHostname)}, csk=<redacted>)"

    companion object {
        /**
         * Convert the decrypted record, taking ownership of its CSK byte array.
         *
         * Not a copy of the field, deliberately: the record has no other reader, so copying here
         * would only double the key in memory. The record must not be kept once this returns.
         */
        fun from(record: ParsedPairingProvision): PairingProvision =
            PairingProvision(
                username = record.username,
                clientHostname = record.clientHostname,
                csk = record.csk,
            )
    }
}
