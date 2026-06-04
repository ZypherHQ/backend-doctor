defmodule BadService do
  def status(name) do
    String.to_atom(name)
  end
end
