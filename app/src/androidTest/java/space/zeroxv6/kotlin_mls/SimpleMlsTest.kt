package space.zeroxv6.kotlin_mls

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Comprehensive instrumented tests for MLS functionality.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class SimpleMlsTest {

    private lateinit var context: Context
    private val testStorages = mutableListOf<String>()

    @Before
    fun setup() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        cleanupTestData()
    }

    @After
    fun cleanup() {
        cleanupTestData()
    }

    private fun cleanupTestData() {
        testStorages.forEach { storageName ->
            val dir = File(context.filesDir, storageName)
            if (dir.exists()) {
                dir.deleteRecursively()
            }
        }
        testStorages.clear()
    }

    private fun createTestService(name: String): MlsService {
        testStorages.add(name)
        return MlsService(context, name)
    }

    // ================================================================
    // 1. Identity creation
    // ================================================================

    @Test
    fun test1_IdentityCreation() = runBlocking {
        println("\n=== Test 1: Identity Creation ===")
        val service = createTestService("test_identity")

        assertFalse("Should not have identity yet", service.hasIdentity())

        service.createIdentity("Alice")

        assertTrue("Should have identity now", service.hasIdentity())
        println("✅ PASS: Identity created")
    }

    // ================================================================
    // 2. Key package generation
    // ================================================================

    @Test
    fun test2_KeyPackageGeneration() = runBlocking {
        println("\n=== Test 2: Key Package Generation ===")
        val service = createTestService("test_kp")

        service.createIdentity("Alice")

        val kp1 = service.generateKeyPackage()
        val kp2 = service.generateKeyPackage()

        assertTrue("Key package should be hex", kp1.matches(Regex("[0-9a-f]+")))
        assertNotEquals("Each key package should be unique", kp1, kp2)

        println("✅ PASS: Key packages generated (${kp1.length} chars each)")
    }

    // ================================================================
    // 3. Group creation
    // ================================================================

    @Test
    fun test3_GroupCreation() = runBlocking {
        println("\n=== Test 3: Group Creation ===")
        val service = createTestService("test_group")

        service.createIdentity("Alice")
        val groupId = service.createGroup()

        assertTrue("Group ID should not be empty", groupId.isNotEmpty())
        assertTrue("Group ID should be hex", groupId.matches(Regex("[0-9a-f]+")))

        val active = service.listActiveGroups()
        assertTrue("Group should be in active list", active.contains(groupId))

        println("✅ PASS: Group created ${groupId.take(16)}...")
    }

    // ================================================================
    // 4. Two-user messaging (Alice → Bob)
    // ================================================================

    @Test
    fun test4_TwoUserMessaging() = runBlocking {
        println("\n=== Test 4: Two-User Messaging ===")
        val alice = createTestService("alice_msg")
        val bob = createTestService("bob_msg")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()

        // Alice adds Bob
        val invite = JSONObject(alice.addMember(groupId, bobKP))
        assertTrue("Invite should have commit", invite.has("commit"))
        assertTrue("Invite should have welcome", invite.has("welcome"))

        // Bob joins
        val bobGroupId = bob.processWelcome(invite.getString("welcome"))
        assertEquals("Group IDs must match", groupId, bobGroupId)

        // Alice → Bob
        val plaintext = "Hello, Bob!"
        val ciphertext = alice.encrypt(groupId, plaintext)
        val decrypted = bob.decrypt(bobGroupId, ciphertext)
        assertEquals("Decrypted must match", plaintext, decrypted)

        println("✅ PASS: Alice → Bob: '$plaintext'")
    }

    // ================================================================
    // 5. Bidirectional messaging
    // ================================================================

    @Test
    fun test5_BidirectionalMessaging() = runBlocking {
        println("\n=== Test 5: Bidirectional Messaging ===")
        val alice = createTestService("alice_bidir")
        val bob = createTestService("bob_bidir")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()

        val invite = JSONObject(alice.addMember(groupId, bobKP))
        val bobGroupId = bob.processWelcome(invite.getString("welcome"))

        // Alice → Bob
        val msg1 = "Hi Bob!"
        assertEquals(msg1, bob.decrypt(bobGroupId, alice.encrypt(groupId, msg1)))
        println("   Alice → Bob: '$msg1' ✓")

        // Bob → Alice
        val msg2 = "Hi Alice!"
        assertEquals(msg2, alice.decrypt(groupId, bob.encrypt(bobGroupId, msg2)))
        println("   Bob → Alice: '$msg2' ✓")

        println("✅ PASS: Bidirectional messaging works")
    }

    // ================================================================
    // 6. Three-user group with commit synchronisation
    // ================================================================

    @Test
    fun test6_ThreeUserGroupWithCommitSync() = runBlocking {
        println("\n=== Test 6: Three-User Group + Commit Sync ===")
        val alice = createTestService("alice_three")
        val bob = createTestService("bob_three")
        val charlie = createTestService("charlie_three")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")
        charlie.createIdentity("Charlie")

        val bobKP = bob.generateKeyPackage()
        val charlieKP = charlie.generateKeyPackage()

        // Alice creates group and adds Bob
        val groupId = alice.createGroup()
        val invite1 = JSONObject(alice.addMember(groupId, bobKP))
        val bobGroupId = bob.processWelcome(invite1.getString("welcome"))
        println("   Bob joined")

        // Alice adds Charlie — Bob MUST process the commit
        val invite2 = JSONObject(alice.addMember(groupId, charlieKP))
        bob.processCommit(bobGroupId, invite2.getString("commit"))
        val charlieGroupId = charlie.processWelcome(invite2.getString("welcome"))
        println("   Charlie joined, Bob processed commit")

        // Alice broadcasts a message — both Bob and Charlie decrypt
        val message = "Hello everyone!"
        val ciphertext = alice.encrypt(groupId, message)
        assertEquals(message, bob.decrypt(bobGroupId, ciphertext))
        assertEquals(message, charlie.decrypt(charlieGroupId, ciphertext))

        println("✅ PASS: Three-user group with proper commit sync")
    }

    // ================================================================
    // 7. Remove member
    // ================================================================

    @Test
    fun test7_RemoveMember() = runBlocking {
        println("\n=== Test 7: Remove Member ===")
        val alice = createTestService("alice_remove")
        val bob = createTestService("bob_remove")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()

        val invite = JSONObject(alice.addMember(groupId, bobKP))
        bob.processWelcome(invite.getString("welcome"))

        // Get Bob's leaf index
        val members = alice.getMembers(groupId)
        val bobMember = members.first { String(it.identity) == "Bob" }

        // Alice removes Bob
        val removeResult = JSONObject(alice.removeMember(groupId, bobMember.index.toUInt()))
        assertTrue("Remove should return commit", removeResult.has("commit"))

        // After removal, group should have 1 member
        val info = JSONObject(alice.getGroupInfo(groupId))
        assertEquals("Should have 1 member left", 1, info.getInt("member_count"))

        println("✅ PASS: Member removed successfully")
    }

    // ================================================================
    // 8. Self-update (key rotation)
    // ================================================================

    @Test
    fun test8_SelfUpdate() = runBlocking {
        println("\n=== Test 8: Self-Update (Key Rotation) ===")
        val alice = createTestService("alice_update")
        val bob = createTestService("bob_update")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()

        val invite = JSONObject(alice.addMember(groupId, bobKP))
        val bobGroupId = bob.processWelcome(invite.getString("welcome"))

        val infoBefore = JSONObject(alice.getGroupInfo(groupId))
        val epochBefore = infoBefore.getLong("epoch")

        // Alice performs self-update
        val updateResult = JSONObject(alice.selfUpdate(groupId))
        assertTrue("Update should return commit", updateResult.has("commit"))

        // Bob processes the update commit
        bob.processCommit(bobGroupId, updateResult.getString("commit"))

        val infoAfter = JSONObject(alice.getGroupInfo(groupId))
        assertTrue("Epoch should advance", infoAfter.getLong("epoch") > epochBefore)

        // Messaging should still work after key rotation
        val msg = "After key rotation"
        assertEquals(msg, bob.decrypt(bobGroupId, alice.encrypt(groupId, msg)))

        println("✅ PASS: Self-update works, messaging continues")
    }

    // ================================================================
    // 9. Get members
    // ================================================================

    @Test
    fun test9_GetMembers() = runBlocking {
        println("\n=== Test 9: Get Members ===")
        val alice = createTestService("alice_members")
        val bob = createTestService("bob_members")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()
        alice.addMember(groupId, bobKP)

        val members = alice.getMembers(groupId)
        assertEquals("Should have 2 members", 2, members.size)

        val names = members.map { String(it.identity) }.toSet()
        assertTrue("Should contain Alice", names.contains("Alice"))
        assertTrue("Should contain Bob", names.contains("Bob"))

        println("✅ PASS: Members listed correctly: $names")
    }

    // ================================================================
    // 10. Identity persistence
    // ================================================================

    @Test
    fun test10_IdentityPersistence() = runBlocking {
        println("\n=== Test 10: Identity Persistence ===")
        val storageName = "test_persist"

        // Session 1 — create identity and save
        run {
            val service = createTestService(storageName)
            service.createIdentity("Alice")
            service.save()
            println("   Saved identity")
        }

        // Session 2 — new instance should restore identity
        run {
            val service2 = MlsService(context, storageName)
            assertTrue("Identity should be restored", service2.hasIdentity())

            // Verify the restored identity works
            val groupId = service2.createGroup()
            assertTrue("Should create group with restored identity", groupId.isNotEmpty())
            println("   Restored identity and created group: ${groupId.take(16)}...")
        }

        println("✅ PASS: Identity persistence works")
    }

    // ================================================================
    // 11. Multiple messages
    // ================================================================

    @Test
    fun test11_MultipleMessages() = runBlocking {
        println("\n=== Test 11: Multiple Messages ===")
        val alice = createTestService("alice_multi")
        val bob = createTestService("bob_multi")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()
        val invite = JSONObject(alice.addMember(groupId, bobKP))
        val bobGroupId = bob.processWelcome(invite.getString("welcome"))

        val messages = listOf(
            "First message",
            "Second message",
            "Emoji test 🚀🔒",
            "Special chars: !@#$%^&*()",
            "Unicode: 你好世界"
        )

        messages.forEach { msg ->
            val ct = alice.encrypt(groupId, msg)
            assertEquals(msg, bob.decrypt(bobGroupId, ct))
            println("   ✓ '$msg'")
        }

        println("✅ PASS: ${messages.size} messages decrypted correctly")
    }

    // ================================================================
    // 12. Error handling — no identity
    // ================================================================

    @Test(expected = MlsServiceException::class)
    fun test12_ErrorNoIdentity() = runBlocking {
        println("\n=== Test 12: Error – No Identity ===")
        val service = createTestService("test_no_id")
        // Should throw because no identity has been created
        service.createGroup()
    }

    // ================================================================
    // 13. Error handling — invalid group
    // ================================================================

    @Test(expected = MlsServiceException::class)
    fun test13_ErrorInvalidGroup() = runBlocking {
        println("\n=== Test 13: Error – Invalid Group ===")
        val service = createTestService("test_bad_group")
        service.createIdentity("Alice")
        service.encrypt("nonexistent-group-id", "test")
    }

    // ================================================================
    // 14. Long message
    // ================================================================

    @Test
    fun test14_LongMessage() = runBlocking {
        println("\n=== Test 14: Long Message ===")
        val alice = createTestService("alice_long")
        val bob = createTestService("bob_long")

        alice.createIdentity("Alice")
        bob.createIdentity("Bob")

        val bobKP = bob.generateKeyPackage()
        val groupId = alice.createGroup()
        val invite = JSONObject(alice.addMember(groupId, bobKP))
        val bobGroupId = bob.processWelcome(invite.getString("welcome"))

        val longMsg = "A".repeat(10_000)
        val ct = alice.encrypt(groupId, longMsg)
        val decrypted = bob.decrypt(bobGroupId, ct)
        assertEquals("Long message must match", longMsg, decrypted)

        println("✅ PASS: 10 000-char message works")
    }
}
