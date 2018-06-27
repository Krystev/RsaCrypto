How to
To get a Git project into your build:

Step 1. Add the JitPack repository to your build file

Gradle:

Add it in your root build.gradle at the end of repositories:

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

Maven:
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
