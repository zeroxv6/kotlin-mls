package space.zeroxv6.kotlin_mls
//
//import android.content.Context
//import androidx.test.ext.junit.runners.AndroidJUnit4
//import androidx.test.platform.app.InstrumentationRegistry
//import kotlinx.coroutines.runBlocking
//import org.json.JSONObject
//import org.junit.After
//import org.junit.Assert.*
//import org.junit.Before
//import org.junit.Test
//import org.junit.runner.RunWith
//import space.zeroxv6.kotlin_mls.MlsService
//import java.io.File
//
///**
// * Comprehensive test suite for OpenMLS Kotlin Bridge
// *
// * Tests cover:
// * 1. Basic operations (identity, group creation)
// * 2. Single-user messaging
// * 3. Multi-user groups
// * 4. State persistence
// * 5. Error handling
// */
//@RunWith(AndroidJUnit4::class)
//class MlsServiceTest {
//
//    private lateinit var context: Context
//    private val testStorages = mutableListOf<String>()
//
//    @Before
//    fun setup() {
//        context = InstrumentationRegistry.getInstrumentation().targetContext
//        cleanupTestData()
//    }
//
//    @After
//    fun cleanup() {
//        cleanupTestData()
//    }
//
//    private fun cleanupTestData() {
//        testStorages.forEach { storageName ->
//            val dir = File(context.filesDir, storageName)
//            if (dir.exists()) {
//                dir.deleteRecursively()
//            }
//        }
//        testStorages.clear()
//    }
//
//    private fun createTestService(name: String): MlsService {
//        testStorages.add(name)
//        return MlsService(context, name)
//    }
//
//    // ========================================
//    // Test 1: Basic Identity Creation
//    // ========================================
//
//    @Test
//    fun testIdentityCreation() = runBlocking {
//        val service = createTestService("test_identity")
//
//        val keyPackage = service.generateIdentity("Alice")
//
//        // Key package should be a non-empty hex string
//        assertNotNull("Key package should not be null", keyPackage)
//        assertTrue("Key package should not be empty", keyPackage.isNotEmpty())
//        assertTrue("Key package should be hex", keyPackage.matches(Regex("[0-9a-f]+")))
//
//        println("✅ Test 1 Passed: Identity created with key package length: ${keyPackage.length}")
//    }
//
//    // ========================================
//    // Test 2: Group Creation
//    // ========================================
//
//    @Test
//    fun testGroupCreation() = runBlocking {
//        val service = createTestService("test_group_creation")
//
//        service.generateIdentity("Alice")
//        val groupId = service.createGroup("my-group")
//
//        assertNotNull("Group ID should not be null", groupId)
//        assertTrue("Group ID should not be empty", groupId.isNotEmpty())
//        assertTrue("Group ID should be hex", groupId.matches(Regex("[0-9a-f]+")))
//
//        println("✅ Test 2 Passed: Group created with ID: ${groupId.take(16)}...")
//    }
//
//    // ========================================
//    // Test 3: Single User Encryption/Decryption
//    // ========================================
//
//    @Test
//    fun testSingleUserMessaging() = runBlocking {
//        val service = createTestService("test_single_user")
//
//        service.generateIdentity("Alice")
//        val groupId = service.createGroup("solo-group")
//
//        val plaintext = "Hello, World!"
//        val ciphertext = service.encrypt(groupId, plaintext)
//
//        assertNotNull("Ciphertext should not be null", ciphertext)
//        assertTrue("Ciphertext should not be empty", ciphertext.isNotEmpty())
//        assertNotEquals("Ciphertext should differ from plaintext", plaintext, ciphertext)
//
//        val decrypted = service.decrypt(groupId, ciphertext)
//
//        assertEquals("Decrypted message should match original", plaintext, decrypted)
//
//        println("✅ Test 3 Passed: Single user messaging works")
//        println("   Original: $plaintext")
//        println("   Encrypted: ${ciphertext.take(40)}...")
//        println("   Decrypted: $decrypted")
//    }
//
//    // ========================================
//    // Test 4: Two User Group Communication
//    // ========================================
//
//    @Test
//    fun testTwoUserGroup() = runBlocking {
//        val alice = createTestService("alice_two_user")
//        val bob = createTestService("bob_two_user")
//
//        // Alice creates identity and group
//        alice.generateIdentity("Alice")
//        val groupId = alice.createGroup("team-chat")
//        println("📝 Alice created group: ${groupId.take(16)}...")
//
//        // Bob creates identity
//        val bobKeyPackage = bob.generateIdentity("Bob")
//        println("📝 Bob created identity")
//
//        // Alice adds Bob to the group
//        val inviteJson = alice.addMember(groupId, bobKeyPackage)
//        val invite = JSONObject(inviteJson)
//
//        assertTrue("Invite should contain 'welcome'", invite.has("welcome"))
//        assertTrue("Invite should contain 'commit'", invite.has("commit"))
//
//        val welcomeHex = invite.getString("welcome")
//        val commitHex = invite.getString("commit")
//
//        println("📝 Alice invited Bob")
//        println("   Welcome length: ${welcomeHex.length}")
//        println("   Commit length: ${commitHex.length}")
//
//        // Bob processes the Welcome message
//        val bobGroupId = bob.processWelcome(welcomeHex)
//
//        assertNotNull("Bob's group ID should not be null", bobGroupId)
//        assertEquals("Group IDs should match", groupId, bobGroupId)
//
//        println("📝 Bob joined group: ${bobGroupId.take(16)}...")
//
//        // Alice sends a message
//        val message = "Hi Bob!"
//        val ciphertext = alice.encrypt(groupId, message)
//        println("📝 Alice encrypted message")
//
//        // Bob decrypts the message
//        val decrypted = bob.decrypt(bobGroupId, ciphertext)
//
//        assertEquals("Bob should receive Alice's message", message, decrypted)
//
//        println("✅ Test 4 Passed: Two-user communication works")
//        println("   Alice → Bob: '$message'")
//        println("   Bob received: '$decrypted'")
//    }
//
//    // ========================================
//    // Test 5: Three User Group
//    // ========================================
//
//    @Test
//    fun testThreeUserGroup() = runBlocking {
//        val alice = createTestService("alice_three")
//        val bob = createTestService("bob_three")
//        val charlie = createTestService("charlie_three")
//
//        // Setup identities
//        alice.generateIdentity("Alice")
//        val bobKP = bob.generateIdentity("Bob")
//        val charlieKP = charlie.generateIdentity("Charlie")
//
//        // Alice creates group
//        val groupId = alice.createGroup("team")
//        println("📝 Alice created group")
//
//        // Alice adds Bob
//        val invite1 = JSONObject(alice.addMember(groupId, bobKP))
//        val bobGroupId = bob.processWelcome(invite1.getString("welcome"))
//        println("📝 Bob joined")
//
//        // Alice adds Charlie
//        val invite2 = JSONObject(alice.addMember(groupId, charlieKP))
//        val charlieGroupId = charlie.processWelcome(invite2.getString("welcome"))
//        println("📝 Charlie joined")
//
//        // Verify all have same group ID
//        assertEquals("All members should have same group ID", groupId, bobGroupId)
//        assertEquals("All members should have same group ID", groupId, charlieGroupId)
//
//        // Alice broadcasts message
//        val message = "Hello everyone!"
//        val ciphertext = alice.encrypt(groupId, message)
//
//        // Bob and Charlie decrypt
//        val bobReceived = bob.decrypt(bobGroupId, ciphertext)
//        val charlieReceived = charlie.decrypt(charlieGroupId, ciphertext)
//
//        assertEquals("Bob should receive message", message, bobReceived)
//        assertEquals("Charlie should receive message", message, charlieReceived)
//
//        println("✅ Test 5 Passed: Three-user group works")
//        println("   Alice → All: '$message'")
//        println("   Bob received: '$bobReceived'")
//        println("   Charlie received: '$charlieReceived'")
//    }
//
//    // ========================================
//    // Test 6: State Persistence
//    // ========================================
//
//    @Test
//    fun testStatePersistence() = runBlocking {
//        val storageName = "test_persistence"
//
//        // Phase 1: Create and save state
//        run {
//            val service = createTestService(storageName)
//            service.generateIdentity("Alice")
//            val groupId = service.createGroup("persistent-group")
//
//            val message = "Test message"
//            val ciphertext = service.encrypt(groupId, message)
//            val decrypted = service.decrypt(groupId, ciphertext)
//
//            assertEquals("Message should work before save", message, decrypted)
//
//            service.save()
//            println("📝 Saved state with group: ${groupId.take(16)}...")
//        }
//
//        // Phase 2: Load state in new instance
//        run {
//            val service2 = createTestService(storageName)
//            // State is auto-loaded in constructor
//
//            // We need to know the group ID - in real app, you'd store this separately
//            // For test, we can list the storage directory
//            val storageDir = File(context.filesDir, storageName)
//            val groupFiles = storageDir.listFiles { file -> file.extension == "json" }
//
//            assertNotNull("Should have saved group files", groupFiles)
//            assertTrue("Should have at least one group", groupFiles!!.isNotEmpty())
//
//            val groupId = groupFiles.first().nameWithoutExtension
//            println("📝 Loaded group: ${groupId.take(16)}...")
//
//            // Try to use the loaded group
//            val message = "After reload"
//            val ciphertext = service2.encrypt(groupId, message)
//            val decrypted = service2.decrypt(groupId, ciphertext)
//
//            assertEquals("Message should work after reload", message, decrypted)
//
//            println("✅ Test 6 Passed: State persistence works")
//        }
//    }
//
//    // ========================================
//    // Test 7: Multiple Messages
//    // ========================================
//
//    @Test
//    fun testMultipleMessages() = runBlocking {
//        val alice = createTestService("alice_multi")
//        val bob = createTestService("bob_multi")
//
//        // Setup two-user group
//        alice.generateIdentity("Alice")
//        val bobKP = bob.generateIdentity("Bob")
//        val groupId = alice.createGroup("chat")
//
//        val invite = JSONObject(alice.addMember(groupId, bobKP))
//        val bobGroupId = bob.processWelcome(invite.getString("welcome"))
//
//        // Send multiple messages
//        val messages = listOf(
//            "First message",
//            "Second message",
//            "Third message with emoji 🚀",
//            "Message with special chars: !@#$%"
//        )
//
//        messages.forEach { message ->
//            val ciphertext = alice.encrypt(groupId, message)
//            val decrypted = bob.decrypt(bobGroupId, ciphertext)
//
//            assertEquals("Message should match: $message", message, decrypted)
//            println("   ✓ '$message' → decrypted correctly")
//        }
//
//        println("✅ Test 7 Passed: Multiple messages work")
//    }
//
//    // ========================================
//    // Test 8: Bidirectional Communication
//    // ========================================
//
//    @Test
//    fun testBidirectionalCommunication() = runBlocking {
//        val alice = createTestService("alice_bidirectional")
//        val bob = createTestService("bob_bidirectional")
//
//        // Setup
//        alice.generateIdentity("Alice")
//        val bobKP = bob.generateIdentity("Bob")
//        val groupId = alice.createGroup("chat")
//
//        val invite = JSONObject(alice.addMember(groupId, bobKP))
//        val bobGroupId = bob.processWelcome(invite.getString("welcome"))
//
//        // Alice → Bob
//        val aliceMessage = "Hi Bob!"
//        val aliceCiphertext = alice.encrypt(groupId, aliceMessage)
//        val bobReceived = bob.decrypt(bobGroupId, aliceCiphertext)
//        assertEquals("Bob should receive Alice's message", aliceMessage, bobReceived)
//        println("   Alice → Bob: '$aliceMessage' ✓")
//
//        // Bob → Alice
//        val bobMessage = "Hi Alice!"
//        val bobCiphertext = bob.encrypt(bobGroupId, bobMessage)
//        val aliceReceived = alice.decrypt(groupId, bobCiphertext)
//        assertEquals("Alice should receive Bob's message", bobMessage, aliceReceived)
//        println("   Bob → Alice: '$bobMessage' ✓")
//
//        println("✅ Test 8 Passed: Bidirectional communication works")
//    }
//
//    // ========================================
//    // Test 9: Error Handling - Invalid Group ID
//    // ========================================
//
//    @Test(expected = Exception::class)
//    fun testInvalidGroupId() = runBlocking {
//        val service = createTestService("test_error")
//        service.generateIdentity("Alice")
//
//        // Try to encrypt with non-existent group
//        service.encrypt("invalid-group-id", "test")
//
//        // Should throw exception
//    }
//
//    // ========================================
//    // Test 10: Long Message
//    // ========================================
//
//    @Test
//    fun testLongMessage() = runBlocking {
//        val service = createTestService("test_long")
//        service.generateIdentity("Alice")
//        val groupId = service.createGroup("long-message-group")
//
//        // Create a long message (1000 characters)
//        val longMessage = "Hello! ".repeat(150).take(1000)
//
//        val ciphertext = service.encrypt(groupId, longMessage)
//        val decrypted = service.decrypt(groupId, ciphertext)
//
//        assertEquals("Long message should decrypt correctly", longMessage, decrypted)
//
//        println("✅ Test 10 Passed: Long message (${longMessage.length} chars) works")
//    }
//
//    // ========================================
//    // Test 11: Sequential Group Operations
//    // ========================================
//
//    @Test
//    fun testSequentialOperations() = runBlocking {
//        val alice = createTestService("alice_sequential")
//        val bob = createTestService("bob_sequential")
//        val charlie = createTestService("charlie_sequential")
//
//        alice.generateIdentity("Alice")
//        val bobKP = bob.generateIdentity("Bob")
//        val charlieKP = charlie.generateIdentity("Charlie")
//
//        // Create group
//        val groupId = alice.createGroup("team")
//        println("1. ✓ Group created")
//
//        // Add Bob
//        val invite1 = JSONObject(alice.addMember(groupId, bobKP))
//        bob.processWelcome(invite1.getString("welcome"))
//        println("2. ✓ Bob added")
//
//        // Send message to Bob
//        val msg1 = alice.encrypt(groupId, "Welcome Bob!")
//        bob.decrypt(groupId, msg1)
//        println("3. ✓ Message to Bob")
//
//        // Add Charlie
//        val invite2 = JSONObject(alice.addMember(groupId, charlieKP))
//        charlie.processWelcome(invite2.getString("welcome"))
//        println("4. ✓ Charlie added")
//
//        // Send message to all
//        val msg2 = alice.encrypt(groupId, "Hello everyone!")
//        bob.decrypt(groupId, msg2)
//        charlie.decrypt(groupId, msg2)
//        println("5. ✓ Broadcast message")
//
//        // Save state
//        alice.save()
//        bob.save()
//        charlie.save()
//        println("6. ✓ All states saved")
//
//        println("✅ Test 11 Passed: Sequential operations work")
//    }
//
//    // ========================================
//    // Performance Test
//    // ========================================
//
//    @Test
//    fun testPerformance() = runBlocking {
//        val service = createTestService("test_performance")
//        service.generateIdentity("Alice")
//        val groupId = service.createGroup("perf-test")
//
//        val messageCount = 100
//        val message = "Performance test message"
//
//        val startTime = System.currentTimeMillis()
//
//        repeat(messageCount) {
//            val ciphertext = service.encrypt(groupId, message)
//            val decrypted = service.decrypt(groupId, ciphertext)
//            assertEquals(message, decrypted)
//        }
//
//        val endTime = System.currentTimeMillis()
//        val duration = endTime - startTime
//        val avgTime = duration.toDouble() / messageCount
//
//        println("✅ Performance Test Passed")
//        println("   Messages: $messageCount")
//        println("   Total time: ${duration}ms")
//        println("   Average: ${String.format("%.2f", avgTime)}ms per message")
//
//        // Sanity check - should be reasonably fast
//        assertTrue("Average time should be under 100ms", avgTime < 100)
//    }
//}