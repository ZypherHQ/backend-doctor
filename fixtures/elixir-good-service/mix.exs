defmodule GoodService.MixProject do
  use Mix.Project

  def project do
    [
      app: :good_service,
      version: "0.1.0",
      elixir: "~> 1.16",
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.8.0"}
    ]
  end
end
