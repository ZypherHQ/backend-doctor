defmodule GoodServiceWeb.UserController do
  use Phoenix.Controller, formats: [:json]

  def index(conn, params) do
    status = Map.get(params, "status", "active")
    json(conn, %{users: list_users(status)})
  end

  def show(conn, %{"id" => id}) do
    json(conn, %{user: find_user(id)})
  end

  defp list_users(status) when status in ["active", "disabled"] do
    []
  end

  defp list_users(_status), do: []

  defp find_user(id), do: %{id: id}
end
