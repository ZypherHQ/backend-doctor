fun findUser(id: String, jdbc: java.sql.Connection) {
    jdbc.createStatement().executeQuery("SELECT * FROM users WHERE id = $id")
}
