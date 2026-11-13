package dev.rourunisen.tapauth.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins both halves of the constructor contract the Rust JNI layer relies on when it builds
 * `ParsedAuthRequest`, `ParsedPairingProvision` and `ParsedPairingResponse` with `NewObject`.
 *
 * `shared/src/jni/objects.rs` builds those DTOs by class name plus a hard-coded descriptor, then
 * passes its arguments **positionally**, and a mismatch is only discoverable on a device:
 * `find_class`/`new_object` fails at runtime and the JNI entry point throws `IllegalStateException`
 * with no compile-time signal on either side. Reflecting over the Kotlin constructors is the only
 * way to prove the two halves agree without a device.
 *
 * The contract has two halves, and neither is enough alone:
 *
 * 1. **The descriptor** (what `NewObject` looks up) catches a renamed class, a wrong arity, a
 *    retyped field and — through `constructors.single()` — a defaulted field, which Kotlin compiles
 *    to an extra synthetic constructor.
 * 2. **The parameter names, in order** (what `NewObject` fills, slot by slot) catch the case the
 *    descriptor cannot see at all: a swap between two fields of the *same* type. Reordering
 *    `hashAlgorithm` and `symmetricAlgorithm` in `ParsedPairingResponse`, or `pamService` /
 *    `processName` / `commandPreview` in `ParsedAuthRequest`, leaves the signature byte-for-byte
 *    identical, `NewObject` succeeds, and the phone silently persists the wrong values — pairing
 *    "works" and every packet is then dropped on an algorithm mismatch.
 *
 * Both lists must be spelled out here independently of the classes under test — deriving them from
 * the same reflection used to check them would assert nothing.
 */
class JniDescriptorTest {

    @Test
    fun parsedAuthRequestConstructorMatchesRustDescriptor() {
        assertEquals(
            "shared/src/jni/objects.rs create_parsed_auth_request builds " +
                "([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
            "([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
            constructorDescriptor(ParsedAuthRequest::class.java),
        )
    }

    @Test
    fun parsedPairingProvisionConstructorMatchesRustDescriptor() {
        assertEquals(
            "shared/src/jni/objects.rs create_parsed_pairing_provision builds " +
                "([BLjava/lang/String;Ljava/lang/String;)V",
            "([BLjava/lang/String;Ljava/lang/String;)V",
            constructorDescriptor(ParsedPairingProvision::class.java),
        )
    }

    @Test
    fun parsedPairingResponseConstructorMatchesRustDescriptor() {
        assertEquals(
            "shared/src/jni/objects.rs create_parsed_pairing_response builds " +
                "(Ljava/lang/String;[BIII)V",
            "(Ljava/lang/String;[BIII)V",
            constructorDescriptor(ParsedPairingResponse::class.java),
        )
    }

    @Test
    fun parsedAuthRequestConstructorTakesRustArgumentsInOrder() {
        assertEquals(
            "create_parsed_auth_request passes challenge, username, hostname, " +
                "timestamp_unix_seconds, pam_service, process_name, command_preview, tty_present " +
                "positionally; the three adjacent Strings are indistinguishable by descriptor",
            listOf(
                "challenge",
                "username",
                "hostname",
                "timestampUnixSeconds",
                "pamService",
                "processName",
                "commandPreview",
                "ttyPresent",
            ),
            parameterNames(ParsedAuthRequest::class.java),
        )
    }

    @Test
    fun parsedPairingProvisionConstructorTakesRustArgumentsInOrder() {
        assertEquals(
            "create_parsed_pairing_provision passes csk, username, client_hostname " +
                "positionally; username/clientHostname share a JVM type",
            listOf("csk", "username", "clientHostname"),
            parameterNames(ParsedPairingProvision::class.java),
        )
    }

    @Test
    fun parsedPairingResponseConstructorTakesRustArgumentsInOrder() {
        assertEquals(
            "create_parsed_pairing_response passes sas, client_ed25519_public_key, " +
                "symmetric_algorithm, hash_algorithm, signature_algorithm positionally; the three " +
                "trailing ints are indistinguishable by descriptor, so a swap here would persist " +
                "the wrong algorithms and silently drop every later packet",
            listOf(
                "sas",
                "clientEd25519PublicKey",
                "symmetricAlgorithm",
                "hashAlgorithm",
                "signatureAlgorithm",
            ),
            parameterNames(ParsedPairingResponse::class.java),
        )
    }

    /**
     * The single JVM constructor descriptor of [clazz].
     *
     * `single()` is deliberate: a Kotlin default value on any field adds a synthetic constructor,
     * and Rust calls exactly one, so a second constructor has to fail here rather than shadow the
     * one the JNI layer uses.
     */
    private fun constructorDescriptor(clazz: Class<*>): String {
        val constructor = clazz.constructors.single()
        val parameters = constructor.parameterTypes.joinToString("") { typeDescriptor(it) }
        return "($parameters)V"
    }

    /**
     * The primary constructor's parameter names, in declaration order.
     *
     * Requires `javaParameters = true` (`app/build.gradle.kts`): without the `MethodParameters`
     * attribute the JVM reports no parameter names and this reads back `arg0`, `arg1`, … instead.
     */
    private fun parameterNames(clazz: Class<*>): List<String> =
        clazz.constructors.single().parameters.map { it.name }

    /** JVM field-descriptor of [type], for the types the pairing/auth DTOs use. */
    private fun typeDescriptor(type: Class<*>): String =
        when (type) {
            ByteArray::class.java -> "[B"
            Int::class.javaPrimitiveType -> "I"
            Long::class.javaPrimitiveType -> "J"
            Boolean::class.javaPrimitiveType -> "Z"
            String::class.java -> "Ljava/lang/String;"
            else -> throw AssertionError("Unsupported constructor parameter type ${type.name}")
        }
}
