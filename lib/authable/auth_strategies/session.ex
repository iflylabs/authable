defmodule Authable.AuthStrategy.Session do
  @moduledoc """
  Authable Strategy implements behaviour Authable.Strategy to check 'session'
  based authencations to find resource owner.
  """

  import Plug.Conn, only: [fetch_session: 1, get_session: 2]

  @behaviour Authable.AuthStrategy
  @auth_strategies Application.get_env(:authable, :auth_strategies)
  @session_auth Map.get(@auth_strategies, :sessions)

  @doc """
  Finds resource owner using configured 'session' keys. Returns nil if
  either no keys are configured or key value not found in the session.
  And, it returns `Authable.Model.User` on sucess,
  `{:error, Map, :http_status_code}` on fails.
  """
  def authenticate(conn, required_scopes) do
    unless is_nil(@session_auth) do
      authenticate_via_session(conn, @session_auth, required_scopes)
    end
  end

  defp authenticate_via_session(conn, session_auth, required_scopes) do
    [subdomain | _] = String.split(conn.host, ".")
    Enum.find_value(session_auth, fn {key, module} ->
      session_value = conn |> fetch_session |> get_session(key)
      if !is_nil(session_value) do
        module.authenticate(subdomain, session_value, required_scopes)
      end
    end)
  end
end
