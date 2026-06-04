module Api
  class UsersController < ApplicationController
    def index
      users = User.find_by_sql("SELECT * FROM users WHERE email LIKE '%#{params[:q]}%'")
      render json: users
    end

    def show
      user = User.find_by!(id: params.require(:id))
      render json: user
    end
  end
end
