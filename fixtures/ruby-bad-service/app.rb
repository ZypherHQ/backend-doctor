class Users
  def find(id)
    ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")
  end
end
