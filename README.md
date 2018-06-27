[![](https://jitpack.io/v/krystev/rsacrypto.svg)](https://jitpack.io/#krystev/rsacrypto)

# How to get a Git project into your build:

Step 1. Add the JitPack repository to your build file

### Gradle:

Step 1. Add it in your root build.gradle at the end of repositories:

	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
Step 2. Add the dependency

	dependencies {
	        implementation 'com.github.krystev:rsacrypto:v1.0'
	}

### Maven:

Step 1. Add the JitPack repository to your build file

	<repositories>
		<repository>
		    <id>jitpack.io</id>
		    <url>https://jitpack.io</url>
		</repository>
	</repositories>
	
Step 2. Add the dependency

	<dependency>
	    <groupId>com.github.krystev</groupId>
	    <artifactId>rsacrypto</artifactId>
	    <version>v1.0</version>
	</dependency>
	
# How to use it

Init your cipher by creating RsaContext with parameters you want to use such as algorithm, mode, keylength, padding and pass it into RsaCipher constructor together with your key store alias name:

            RsaContext rsaContext = new RsaContextBuilder()
                    .setAlgorithm(RsaContext.Algorithm.RSA)
                    .setMode(RsaContext.Mode.ECB)
                    .setKeyLength(RsaContext.KeyLength.BITS_2048)
                    .setPadding(RsaContext.Padding.NO_PADDING)
                    .build();

            RsaCipher rsaCipher = new RsaCipher(rsaContext, KEY_STORE_ALIAS);
    
## Encrypt data
Encrypt data using public or private key:

	String encryptedData = rsaCipher.encryptByPublicKey(data);
	
or
	
	String encryptedData = rsaCipher.encryptByPrivateKey(data);
	
## Decrypt data
Decrypt data with private key if you have been encrypted it with public key before:
	
	String decryptedData = rsaCipher.decryptByPrivateKey(data);
	
or decrypt it with public key if you have been encrypted it with private key:

	String decryptedData = rsaCipher.decryptByPublicKey(data);

## Set keys from string
You can set your keys from string format, both should be pair

	rsaCipher.setPrivateKey(YOUR_KEY_AS_STRING);

	rsaCipher.setPublicKey(YOUR_KEY_AS_STRING);
