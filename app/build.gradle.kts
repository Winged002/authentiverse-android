@file:Suppress("UnstableApiUsage")

val pkg: String = providers.gradleProperty("wireguardPackageName").get()

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = pkg
    compileSdk = 36

    defaultConfig {
        applicationId = pkg
        minSdk = 24
        targetSdk = 36
        versionCode = providers.gradleProperty("wireguardVersionCode").get().toInt()
        versionName = providers.gradleProperty("wireguardVersionName").get()
        vectorDrawables.useSupportLibrary = true
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "IDQA_CORE_ROOT_SHA256", "\"${providers.gradleProperty("authentiverseIdqaRootSha256").orElse("").get()}\"")
        buildConfigField("String", "AUTHENTIVERSE_UPDATE_MANIFEST_URL", "\"${providers.gradleProperty("authentiverseUpdateManifestUrl").orElse("").get()}\"")
        buildConfigField("String", "AUTHENTIVERSE_UPDATE_SIGNER_SHA256", "\"${providers.gradleProperty("authentiverseUpdateSignerSha256").orElse("").get()}\"")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging.resources.excludes += setOf(
        "META-INF/DEPENDENCIES", "META-INF/NOTICE*", "META-INF/LICENSE*",
        "DebugProbesKt.bin", "kotlin-tooling-metadata.json"
    )

    lint {
        abortOnError = true
        disable += "LongLogTag"
    }
}

dependencies {
    implementation("com.wireguard.android:tunnel:1.0.20260102")
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.documentfile)
    implementation(libs.google.material)
    implementation(libs.kotlinx.coroutines.android)
    coreLibraryDesugaring(libs.desugarJdkLibs)
    testImplementation(libs.junit)
}
