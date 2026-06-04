defmodule GoodServiceWeb.Admin.ReportController do
  use Phoenix.Controller, formats: [:json]

  def index(conn, params) do
    status = Map.get(params, "status", "open")
    json(conn, %{reports: list_reports(status)})
  end

  def show(conn, %{"id" => id}) do
    json(conn, %{report: find_report(id)})
  end

  def create(conn, %{"report" => report_params}) do
    conn
    |> put_status(:created)
    |> json(%{report: create_report(report_params)})
  end

  def update(conn, %{"id" => id, "report" => report_params}) do
    json(conn, %{report: update_report(id, report_params)})
  end

  defp list_reports(status) when status in ["open", "closed"], do: []
  defp list_reports(_status), do: []

  defp find_report(id), do: %{id: id, status: "open"}
  defp create_report(params), do: Map.take(params, ["title", "status"])
  defp update_report(id, params), do: Map.put(Map.take(params, ["title", "status"]), "id", id)
end
