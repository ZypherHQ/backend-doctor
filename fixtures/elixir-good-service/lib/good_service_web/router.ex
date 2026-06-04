defmodule GoodServiceWeb.Router do
  use Phoenix.Router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/api", GoodServiceWeb do
    pipe_through :api

    resources "/users", UserController, only: [:index, :show]
  end

  scope "/admin", GoodServiceWeb.Admin, as: :admin do
    pipe_through :api

    resources "/reports", ReportController, except: [:delete]
  end
end
