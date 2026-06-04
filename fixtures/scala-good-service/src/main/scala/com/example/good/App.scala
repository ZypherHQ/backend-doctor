package com.example.good

import java.sql.Connection

final case class UserSummary(id: String, displayName: String)

final class UserRepository(connection: Connection) {
  def find(id: String): Option[UserSummary] = {
    val statement =
      connection.prepareStatement("SELECT id, display_name FROM users WHERE id = ?")
    statement.setString(1, id)
    val rows = statement.executeQuery()
    if (rows.next()) {
      Some(UserSummary(rows.getString("id"), rows.getString("display_name")))
    } else {
      None
    }
  }
}
