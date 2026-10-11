package app.cipher.messenger.net

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** ST-060: a rotation makes the next SOCKS connection present a different credential (Tor builds a different circuit per credential). TEST DOUBLE proxy. */
class CircuitIsolationTest {
    private val users = CopyOnWriteArrayList<String>()
    private lateinit var proxy: ServerSocket

    @Before fun start() {
        proxy = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) {
            while (!proxy.isClosed) {
                val c = runCatching { proxy.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching {
                        c.use { s ->
                            val i = s.getInputStream()
                            val o = s.getOutputStream()
                            val methods = i.readNBytes(2).let { i.readNBytes(it[1].toInt() and 0xff) }
                            if (methods.contains(2)) {
                                o.write(byteArrayOf(5, 2)) // username/password
                                i.read() // version 1
                                users += String(i.readNBytes(i.read()))
                                i.readNBytes(i.read())
                                o.write(byteArrayOf(1, 0))
                            } else {
                                o.write(byteArrayOf(5, 0))
                                users += "(none)"
                            }
                            // answer nothing more: the client's connect fails, which is irrelevant here
                        }
                    }
                }
            }
        }
    }

    @After fun stop() = proxy.close()

    private fun connectOnce() {
        val sock = Socket(java.net.Proxy(java.net.Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxy.localPort)))
        sock.soTimeout = 3000
        runCatching { sock.connect(InetSocketAddress.createUnresolved("relay.example", 443), 3000) }
        runCatching { sock.close() }
    }

    @Test fun a_rotation_changes_the_credential_the_proxy_sees() {
        val iso = CircuitIsolation(proxy.localPort)
        iso.install()
        connectOnce()
        connectOnce()
        iso.rotate()
        connectOnce()
        val deadline = System.currentTimeMillis() + 5000
        while (users.size < 3 && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertEquals(3, users.size)
        assertEquals("same epoch, same circuit", users[0], users[1])
        assertNotEquals("after a rotation a fresh circuit is requested", users[1], users[2])
        assertTrue("the credential is an opaque random token", users[0].matches(Regex("[0-9a-f]{16}")))
        assertEquals(1, iso.rotationCount())
    }

    @Test fun tokens_are_random_and_carry_no_identity() {
        val a = CircuitIsolation(1).current()
        val b = CircuitIsolation(1).current()
        assertNotEquals(a, b)
    }
}
