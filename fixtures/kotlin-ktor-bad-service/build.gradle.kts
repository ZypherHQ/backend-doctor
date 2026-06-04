plugins {
    application
    kotlin("jvm") version "2.3.0"
}

val ktorVersion = "3.4.3"
val logbackVersion = "1.5.6"

application {
    mainClass.set("com.example.bad.ApplicationKt")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("ch.qos.logback:logback-classic:$logbackVersion")
}
