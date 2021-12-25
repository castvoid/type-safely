libopencm3 required the patch from

https://github.com/libopencm3/libopencm3/pull/794/commits/f95b6133c27b485523542c0993d914ac6d3f8a1b

to be applied.

The patch is below:
```
diff --git a/include/libopencm3/stm32/common/crypto_common_f24.h b/include/libopencm3/stm32/common/crypto_common_f24.h
index eb885c8f..946396b6 100644
--- a/include/libopencm3/stm32/common/crypto_common_f24.h
+++ b/include/libopencm3/stm32/common/crypto_common_f24.h
@@ -138,11 +138,12 @@ specific memorymap.h header before including this header file.*/
 #define CRYP_MISR		MMIO32(CRYP_BASE + 0x1C)
 
 /* CRYP Key registers (CRYP_KxLR) x=0..3 */
-#define CRYP_KR(i)		MMIO64(CRYP_BASE + 0x20 + (i) * 8)
+#define CRYP_KR(i)		MMIO32(CRYP_BASE + 0x20 + (i) * 4)
+#define CRYP_KR_COUNT   8
 
 /* CRYP Initialization Vector Registers (CRYP_IVxLR) x=0..1 */
-#define CRYP_IVR(i)		MMIO32(CRYP_BASE + 0x40 + (i) * 8)
-
+#define CRYP_IVR(i)		MMIO32(CRYP_BASE + 0x40 + (i) * 4)
+#define CRYP_IVR_COUNT  4
 /* --- CRYP_CR values ------------------------------------------------------ */
 
 /* ALGODIR: Algorithm direction */
@@ -150,7 +151,7 @@ specific memorymap.h header before including this header file.*/
 
 /* ALGOMODE: Algorithm mode */
 #define CRYP_CR_ALGOMODE_SHIFT		3
-#define CRYP_CR_ALGOMODE		(7 << CRYP_CR_ALGOMODE_SHIFT)
+#define CRYP_CR_ALGOMODE		    (7 << CRYP_CR_ALGOMODE_SHIFT)
 #define CRYP_CR_ALGOMODE_TDES_ECB	(0 << CRYP_CR_ALGOMODE_SHIFT)
 #define CRYP_CR_ALGOMODE_TDES_CBC	(1 << CRYP_CR_ALGOMODE_SHIFT)
 #define CRYP_CR_ALGOMODE_DES_ECB	(2 << CRYP_CR_ALGOMODE_SHIFT)
@@ -162,7 +163,7 @@ specific memorymap.h header before including this header file.*/
 
 /* DATATYPE: Data type selection */
 #define CRYP_CR_DATATYPE_SHIFT		6
-#define CRYP_CR_DATATYPE		(3 << CRYP_CR_DATATYPE_SHIFT)
+#define CRYP_CR_DATATYPE		   (3 << CRYP_CR_DATATYPE_SHIFT)
 #define CRYP_CR_DATATYPE_32		(0 << CRYP_CR_DATATYPE_SHIFT)
 #define CRYP_CR_DATATYPE_16		(1 << CRYP_CR_DATATYPE_SHIFT)
 #define CRYP_CR_DATATYPE_8		(2 << CRYP_CR_DATATYPE_SHIFT)
@@ -261,6 +262,12 @@ enum crypto_keysize {
 	CRYPTO_KEY_192BIT,
 	CRYPTO_KEY_256BIT,
 };
+enum key_offset
+{
+	KEY_128BIT_OFFSET = 4,
+	KEY_192BIT_OFFSET = 2,
+	KEY_256BIT_OFFSET = 0,
+};
 enum crypto_datatype {
 
 	CRYPTO_DATA_32BIT = 0,
@@ -271,13 +278,13 @@ enum crypto_datatype {
 
 BEGIN_DECLS
 void crypto_wait_busy(void);
-void crypto_set_key(enum crypto_keysize keysize, uint64_t key[]);
-void crypto_set_iv(uint64_t iv[]);
+void crypto_set_key(enum crypto_keysize keysize, const uint8_t *key);
+void crypto_set_iv(const uint8_t *iv);
 void crypto_set_datatype(enum crypto_datatype datatype);
 void crypto_set_algorithm(enum crypto_mode mode);
 void crypto_start(void);
 void crypto_stop(void);
-uint32_t crypto_process_block(uint32_t *inp, uint32_t *outp, uint32_t length);
+uint32_t crypto_process_block(const uint32_t *inp, uint32_t *outp, uint32_t length);
 END_DECLS
 /**@}*/
 /**@}*/
diff --git a/lib/stm32/common/crypto_common_f24.c b/lib/stm32/common/crypto_common_f24.c
index 22f329c6..c7b3e7fd 100644
--- a/lib/stm32/common/crypto_common_f24.c
+++ b/lib/stm32/common/crypto_common_f24.c
@@ -32,10 +32,10 @@
 
 /**@{*/
 
+#include <string.h>
+#include <libopencmsis/core_cm3.h>
 #include <libopencm3/stm32/crypto.h>
 
-#define CRYP_CR_ALGOMODE_MASK	((1 << 19) | CRYP_CR_ALGOMODE)
-
 /**
  * @brief Wait, if the Controller is busy
  */
@@ -47,37 +47,66 @@ void crypto_wait_busy(void)
 /**
  * @brief Set key value to the controller
  * @param[in] keysize enum crypto_keysize Specified size of the key.
- * @param[in] key uint64_t[] Key value (array of 4 items)
+ * @param[in] key uint8_t* Key value (array of 16 bytes (KEY_SIZE_128BIT) |
+ *                                    array of 24 bytes (KEY_SIZE_192BIT) |
+ *                                    array of 32 bytes (KEY_SIZE_256BIT))
  */
-void crypto_set_key(enum crypto_keysize keysize, uint64_t key[])
+void crypto_set_key(enum crypto_keysize keysize, const uint8_t *key)
 {
 	int i;
+	int j;
 
 	crypto_wait_busy();
 
-	CRYP_CR = (CRYP_CR & ~CRYP_CR_KEYSIZE) |
-		  (keysize << CRYP_CR_KEYSIZE_SHIFT);
+	CRYP_CR = (CRYP_CR & ~CRYP_CR_KEYSIZE) | (keysize << CRYP_CR_KEYSIZE_SHIFT);
+
+	uint32_t *key_32bit_pointer = (uint32_t*)key;
+
+	uint32_t swaped_key[CRYP_KR_COUNT];
+	memset(swaped_key, 0, sizeof(swaped_key));
+
+	switch(keysize)
+	{
+		case CRYPTO_KEY_128BIT:
+			for(i = KEY_128BIT_OFFSET, j = 0; i < CRYP_KR_COUNT; i++, j++) {
+				swaped_key[i] = __REV(key_32bit_pointer[j]);
+			}
+			break;
+		case CRYPTO_KEY_192BIT:
+			for(i = KEY_192BIT_OFFSET, j = 0; i < CRYP_KR_COUNT; i++, j++) {
+				swaped_key[i] = __REV(key_32bit_pointer[j]);
+			}
+			break;
+		case CRYPTO_KEY_256BIT:
+			for(i = KEY_256BIT_OFFSET, j = 0; i < CRYP_KR_COUNT; i++, j++) {
+				swaped_key[i] = __REV(key_32bit_pointer[j]);
+			}
+			break;
+	}
+
 
-	for (i = 0; i < 4; i++) {
-		CRYP_KR(i) = key[i];
+	for (i = 0; i < CRYP_KR_COUNT; i++) {
+		CRYP_KR(i) = swaped_key[i];
 	}
 }
 
 /**
  * @brief Set Initialization Vector
  *
- * @param[in] iv uint64_t[] Initialization vector (array of 4 items)
+ * @param[in] iv uint8_t* Initialization vector (array of 16 items)
 
  * @note Cryptographic controller must be in disabled state
  */
-void crypto_set_iv(uint64_t iv[])
+void crypto_set_iv(const uint8_t *iv)
 {
 	int i;
 
 	crypto_wait_busy();
 
-	for (i = 0; i < 4; i++) {
-		CRYP_IVR(i) = iv[i];
+	uint32_t *iv_32bit_pointer = (uint32_t*)iv;
+
+	for (i = 0; i < CRYP_IVR_COUNT; i++) {
+		CRYP_IVR(i) = __REV(iv_32bit_pointer[i]);
 	}
 }
 
@@ -88,8 +117,7 @@ void crypto_set_iv(uint64_t iv[])
  */
 void crypto_set_datatype(enum crypto_datatype datatype)
 {
-	CRYP_CR = (CRYP_CR & ~CRYP_CR_DATATYPE) |
-		  (datatype << CRYP_CR_DATATYPE_SHIFT);
+	CRYP_CR = (CRYP_CR & ~CRYP_CR_DATATYPE) | (datatype << CRYP_CR_DATATYPE_SHIFT);
 }
 
 /**
@@ -99,12 +127,10 @@ void crypto_set_datatype(enum crypto_datatype datatype)
  */
 void crypto_set_algorithm(enum crypto_mode mode)
 {
-	mode &= ~CRYP_CR_ALGOMODE_MASK;
-
 	if ((mode == DECRYPT_AES_ECB) || (mode == DECRYPT_AES_CBC)) {
 		/* Unroll keys for the AES encoder for the user automatically */
 
-		CRYP_CR = (CRYP_CR & ~CRYP_CR_ALGOMODE_MASK) |
+		CRYP_CR = (CRYP_CR & ~CRYP_CR_ALGOMODE) |
 		    CRYP_CR_ALGOMODE_AES_PREP;
 
 		crypto_start();
@@ -112,7 +138,8 @@ void crypto_set_algorithm(enum crypto_mode mode)
 		/* module switches to DISABLE automatically */
 	}
 	/* set algo mode */
-	CRYP_CR = (CRYP_CR & ~CRYP_CR_ALGOMODE_MASK) | mode;
+	CRYP_CR = (CRYP_CR & ~CRYP_CR_ALGODIR);
+	CRYP_CR = (CRYP_CR & ~CRYP_CR_ALGOMODE) | mode;
 
 	/* flush buffers */
 	CRYP_CR |= CRYP_CR_FFLUSH;
@@ -129,7 +156,6 @@ void crypto_start(void)
 /**
  * @brief Disable the cryptographic controller and stop processing
  */
-
 void crypto_stop(void)
 {
 	CRYP_CR &= ~CRYP_CR_CRYPEN;
@@ -149,7 +175,7 @@ void crypto_stop(void)
  *
  * @returns uint32_t Number of written words
  */
-uint32_t crypto_process_block(uint32_t *inp, uint32_t *outp, uint32_t length)
+uint32_t crypto_process_block(const uint32_t *inp, uint32_t *outp, uint32_t length)
 {
 	uint32_t rd = 0, wr = 0;
 
```