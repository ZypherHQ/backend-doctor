object App {
  def findUser(id: String, db: java.sql.Connection) =
    db.createStatement().executeQuery(s"SELECT * FROM users WHERE id = $id")
}
