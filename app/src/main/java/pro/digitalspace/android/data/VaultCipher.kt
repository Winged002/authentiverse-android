/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.data

import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Windows/macOS compatible DSVLT001 chunked AES-256-GCM stream. */
object VaultCipher {
    const val CHUNK_SIZE = 1024 * 1024
    private val magic = "DSVLT001".encodeToByteArray()

    fun encrypt(input: InputStream, output: OutputStream, key: ByteArray, contentId: String): ByteArray {
        output.write(magic); output.writeIntLE(CHUNK_SIZE)
        val hash = MessageDigest.getInstance("SHA-256")
        val clear = ByteArray(CHUNK_SIZE); var index = 0
        while (true) {
            val count = input.readChunk(clear)
            if (count == 0) break
            hash.update(clear, 0, count)
            val nonce = DigitalSpaceCrypto.random(12)
            val chunk = clear.copyOf(count)
            val sealed = DigitalSpaceCrypto.seal(chunk, key, nonce, "$contentId:$index".encodeToByteArray())
            output.writeIntLE(count); output.write(nonce); output.write(sealed.tag); output.write(sealed.ciphertext)
            chunk.fill(0); sealed.tag.fill(0); sealed.ciphertext.fill(0)
            index++
        }
        output.writeIntLE(0); output.flush(); clear.fill(0)
        return hash.digest()
    }

    fun decrypt(input: InputStream, output: OutputStream, key: ByteArray, contentId: String): ByteArray {
        require(input.readExact(magic.size).contentEquals(magic) && input.readIntLE() == CHUNK_SIZE) { "Invalid protected file." }
        val hash = MessageDigest.getInstance("SHA-256"); var index = 0
        while (true) {
            val count = input.readIntLE(); if (count == 0) break
            require(count in 1..CHUNK_SIZE) { "Invalid protected file chunk." }
            val nonce = input.readExact(12); val tag = input.readExact(16); val ciphertext = input.readExact(count)
            val clear = DigitalSpaceCrypto.open(ciphertext, tag, key, nonce, "$contentId:$index".encodeToByteArray())
            output.write(clear); hash.update(clear); clear.fill(0); index++
        }
        require(input.read() == -1) { "Protected file has trailing data." }
        return hash.digest()
    }

    fun reencrypt(input: InputStream, output: OutputStream, sourceKey: ByteArray, sourceId: String,
                  destinationKey: ByteArray, destinationId: String) {
        require(input.readExact(magic.size).contentEquals(magic) && input.readIntLE() == CHUNK_SIZE) { "Invalid protected source." }
        output.write(magic); output.writeIntLE(CHUNK_SIZE); var index = 0
        while (true) {
            val count = input.readIntLE(); if (count == 0) break
            require(count in 1..CHUNK_SIZE)
            val sourceNonce = input.readExact(12); val sourceTag = input.readExact(16); val sourceCipher = input.readExact(count)
            val clear = DigitalSpaceCrypto.open(sourceCipher, sourceTag, sourceKey, sourceNonce, "$sourceId:$index".encodeToByteArray())
            val nonce = DigitalSpaceCrypto.random(12)
            val sealed = DigitalSpaceCrypto.seal(clear, destinationKey, nonce, "$destinationId:$index".encodeToByteArray())
            output.writeIntLE(count); output.write(nonce); output.write(sealed.tag); output.write(sealed.ciphertext)
            clear.fill(0); sealed.tag.fill(0); sealed.ciphertext.fill(0); index++
        }
        require(input.read() == -1); output.writeIntLE(0); output.flush()
    }

    private fun InputStream.readChunk(buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) { val count = read(buffer, total, buffer.size - total); if (count < 0) break; total += count }
        return total
    }
    private fun InputStream.readExact(count: Int): ByteArray = ByteArray(count).also { buffer ->
        var offset = 0
        while (offset < count) { val read = read(buffer, offset, count - offset); if (read < 0) throw EOFException(); offset += read }
    }
    private fun InputStream.readIntLE() = ByteBuffer.wrap(readExact(4)).order(ByteOrder.LITTLE_ENDIAN).int
    private fun OutputStream.writeIntLE(value: Int) = write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array())
}
