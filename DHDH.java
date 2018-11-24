 public void DHDH() throws Exception {
    // АЛИСА
    	// АЛИСА создаёт ключ 2048 бит
    	SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048, secureRandom);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        
        // АЛИСА создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        // отправляем это Бобу
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded(); 
    // БОБ    
        // Боб из байтов АЛИСЫ формирует её публичный ключ 
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec); 

        // БОБ получает параметры ключа АЛИСЫ и на их основе создаёт пару собственных ключей
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // БОБ создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded(); //+

    // АЛИСА
        // АЛИСА из байтов БОБА формирует его публичный ключ и подключает к общему секрету
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        aliceKeyAgree.doPhase(bobPubKey, true);

    // БОБ
        // подключает её публичный ключ к общему секрету
        bobKeyAgree.doPhase(alicePubKey, true);

    // ОБА
        // формируют общий секрет, он получается одинаковым
       	byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
       	byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
           	throw new Exception("Shared secrets differ");
        System.out.println("Shared secrets are the same");
        
        // теперь на основе общего секрета они могут создать AES ключ
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");			
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

    // БОБ
        // создаёт шифр, применяет его и параметры шифрования
        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
        // нужно передать зашифрованный текст и параметры шифрования
        byte[] ciphertext = bobCipher.doFinal("ПРИМЕР СООБЩЕНИЯ".getBytes());
        byte[] encodedParams = bobCipher.getParameters().getEncoded();

    // АЛИСА 
        // применяет параметры шифрования и свой AES ключ
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);
        
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
        
        byte[] recovered = aliceCipher.doFinal(ciphertext);
        
        // проверка
        if (!java.util.Arrays.equals("ПРИМЕР СООБЩЕНИЯ".getBytes(), recovered))
            throw new Exception("AES in CBC mode recovered text is " +
                    "different from cleartext");
        System.out.println("AES in CBC mode recovered text is " + 
                "same as cleartext" + "\n" + 
        		new String(recovered));
    }
