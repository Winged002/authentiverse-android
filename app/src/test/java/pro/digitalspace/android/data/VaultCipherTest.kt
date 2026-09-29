/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class VaultCipherTest {
    @Test fun roundTripAcrossChunkBoundary() {
        val clear = ByteArray(VaultCipher.CHUNK_SIZE + 37) { (it * 31).toByte() }
        val key = DigitalSpaceCrypto.random(32)
        val encrypted = ByteArrayOutputStream()
        val expectedHash = VaultCipher.encrypt(ByteArrayInputStream(clear), encrypted, key, "file_test")
        val restored = ByteArrayOutputStream()
        val actualHash = VaultCipher.decrypt(ByteArrayInputStream(encrypted.toByteArray()), restored, key, "file_test")
        assertArrayEquals(clear, restored.toByteArray())
        assertArrayEquals(expectedHash, actualHash)
    }

    @Test fun rejectsTampering() {
        val key = DigitalSpaceCrypto.random(32)
        val encrypted = ByteArrayOutputStream().also {
            VaultCipher.encrypt(ByteArrayInputStream("confidential".encodeToByteArray()), it, key, "file_test")
        }.toByteArray()
        encrypted[encrypted.lastIndex - 10] = (encrypted[encrypted.lastIndex - 10].toInt() xor 1).toByte()
        assertThrows(Exception::class.java) {
            VaultCipher.decrypt(ByteArrayInputStream(encrypted), ByteArrayOutputStream(), key, "file_test")
        }
    }
}
