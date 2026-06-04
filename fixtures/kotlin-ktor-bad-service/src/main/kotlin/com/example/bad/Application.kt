package com.example.bad

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.sql.Connection
import java.sql.DriverManager

fun main() {
    embeddedServer(Netty, port = 8080) {
        module(databaseConnection())
    }.start(wait = true)
}

fun Application.module(jdbc: Connection) {
    routing {
        get("/api/users/{id}") {
            val id = call.parameters["id"] ?: return@get call.respond(HttpStatusCode.BadRequest)
            val region = call.request.queryParameters["region"] ?: "global"
            val users = jdbc.createStatement().executeQuery("SELECT id, email FROM users WHERE id = '$id' AND region = '$region'")
            if (users.next()) {
                call.respond(mapOf("id" to users.getString("id"), "email" to users.getString("email")))
            } else {
                call.respond(HttpStatusCode.NotFound)
            }
        }
    }
}

private fun databaseConnection(): Connection =
    DriverManager.getConnection(
        requireNotNull(System.getenv("DATABASE_URL")) {
            "DATABASE_URL is required"
        }
    )
