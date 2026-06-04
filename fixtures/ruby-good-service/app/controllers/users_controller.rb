module Api
  class UsersController < ApplicationController
    def index
      users = User.where(active: true).order(:created_at).limit(50)
      render json: users
    end

    def show
      user = User.find_by!(id: params.require(:id))
      render json: user
    end
  end
end
