package space.zeroxv6.kotlin_mls

import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Local unit tests (no Android device required).
 *
 * Note: The MLS native library requires an Android device or emulator.
 * These tests verify only pure-Kotlin logic. For full MLS tests, run the
 * instrumented test suite: ./gradlew connectedAndroidTest
 */
class MlsServiceTest {

    @Test
    fun exceptionMessageIsDescriptive() {
        val ex = MlsServiceException("test error", RuntimeException("inner"))
        assertNotNull(ex.message)
        assert(ex.message!!.contains("test error"))
        assertNotNull(ex.cause)
    }

    @Test
    fun exceptionFromMlsExceptionStringifiesNicely() {
        val ex = MlsServiceException("outer", RuntimeException("inner detail"))
        assert(ex.message!!.contains("outer"))
    }
}