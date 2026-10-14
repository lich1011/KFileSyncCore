plugins {
    id("com.android.library") version "9.2.1"
    id("maven-publish")
}

android {
    namespace = "com.kfilesync.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add("../build/android/jniLibs")
            kotlin.directories.add("../build/android/kotlin")
        }
    }

    publishing {
        singleVariant("release")
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.14.0@aar")
}

publishing {
    publications {
        create<MavenPublication>("release") {
            afterEvaluate {
                from(components["release"])
            }
            groupId = "com.kfilesync"
            artifactId = "core-android"
            version = providers.environmentVariable("CORE_VERSION").getOrElse("0.1.0")
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/lich1011/KFileSyncCore")
            credentials {
                username = providers.environmentVariable("GITHUB_ACTOR").getOrElse("")
                password = providers.environmentVariable("GITHUB_TOKEN").getOrElse("")
            }
        }
    }
}
