package com.example.good

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.serialization.kotlinx.json.json
import java.sql.DriverManager
import java.sql.Connection
import kotlinx.serialization.Serializable

@Serializable
data class UserUpdateRequest(val displayName: String)

fun main() {
    embeddedServer(Netty, port = portFromEnvironment()) {
        module(databaseConnection())
    }.start(wait = true)
}

fun Application.module(connection: Connection) {
    install(ContentNegotiation) {
        json()
    }
    userRoutes(connection)
}

fun Application.userRoutes(connection: Connection) {
    routing {
        route("/users") {
            get("/{id}") {
                val id = call.parameters["id"] ?: return@get call.respond(HttpStatusCode.BadRequest)
                val region = call.request.queryParameters["region"] ?: "global"
                connection.prepareStatement("SELECT id, display_name FROM users WHERE id = ? AND region = ?")
                    .use { statement ->
                        statement.setString(1, id)
                        statement.setString(2, region)
                        statement.executeQuery().use { rows ->
                            if (rows.next()) {
                                call.respond(mapOf("id" to rows.getString("id")))
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }
                    }
            }

            post("/{id}") {
                val id = call.parameters["id"] ?: return@post call.respond(HttpStatusCode.BadRequest)
                val request = call.receive<UserUpdateRequest>()
                connection.prepareStatement("UPDATE users SET display_name = ? WHERE id = ?")
                    .use { statement ->
                        statement.setString(1, request.displayName)
                        statement.setString(2, id)
                        statement.executeUpdate()
                    }
                call.respond(HttpStatusCode.NoContent)
            }
        }
    }
}

private fun portFromEnvironment(): Int =
    System.getenv("PORT")?.toIntOrNull() ?: 8080

private fun databaseConnection(): Connection =
    DriverManager.getConnection(
        requireNotNull(System.getenv("DATABASE_URL")) {
            "DATABASE_URL is required"
        }
    )
