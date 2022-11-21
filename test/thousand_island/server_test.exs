defmodule ThousandIsland.ServerTest do
  # False due to telemetry raciness
  use ExUnit.Case, async: false

  defmodule Echo do
    use ThousandIsland.Handler

    @impl ThousandIsland.Handler
    def handle_connection(socket, state) do
      {:ok, data} = ThousandIsland.Socket.recv(socket, 0)
      ThousandIsland.Socket.send(socket, data)
      {:close, state}
    end
  end

  defmodule Goodbye do
    use ThousandIsland.Handler

    @impl ThousandIsland.Handler
    def handle_shutdown(socket, state) do
      ThousandIsland.Socket.send(socket, "GOODBYE")
      {:close, state}
    end
  end

  defmodule Error do
    use ThousandIsland.Handler

    @impl ThousandIsland.Handler
    def handle_error(error, _socket, state) do
      # Send error to test process
      case :proplists.get_value(:test_pid, state) do
        pid when is_pid(pid) ->
          send(pid, error)
          :ok

        _ ->
          raise "missing :test_pid for Error handler"
      end
    end
  end

  test "should handle multiple connections as expected" do
    {:ok, _, port} = start_handler(Echo)
    {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)
    {:ok, other_client} = :gen_tcp.connect(:localhost, port, active: false)

    :ok = :gen_tcp.send(client, "HELLO")
    :ok = :gen_tcp.send(other_client, "BONJOUR")

    # Invert the order to ensure we handle concurrently
    assert :gen_tcp.recv(other_client, 0) == {:ok, 'BONJOUR'}
    assert :gen_tcp.recv(client, 0) == {:ok, 'HELLO'}

    :gen_tcp.close(client)
    :gen_tcp.close(other_client)
  end

  describe "shutdown" do
    test "it should stop accepting connections but allow existing ones to complete" do
      {:ok, server_pid, port} = start_handler(Echo)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)
      task = Task.async(fn -> ThousandIsland.stop(server_pid) end)
      # Make sure that the stop has had a chance to shutdown the acceptors
      Process.sleep(100)

      assert :gen_tcp.connect(:localhost, port, [active: false], 100) == {:error, :econnrefused}

      :ok = :gen_tcp.send(client, "HELLO")
      assert :gen_tcp.recv(client, 0) == {:ok, 'HELLO'}
      :gen_tcp.close(client)

      Task.await(task)

      refute Process.alive?(server_pid)
    end

    test "it should give connections a chance to say goodbye" do
      {:ok, server_pid, port} = start_handler(Goodbye)
      {:ok, client} = :gen_tcp.connect(:localhost, port, active: false)

      # Make sure the socket has transitioned ownership to the connection process
      Process.sleep(100)
      task = Task.async(fn -> ThousandIsland.stop(server_pid) end)
      # Make sure that the stop has had a chance to shutdown the acceptors
      Process.sleep(100)

      assert :gen_tcp.recv(client, 0) == {:ok, 'GOODBYE'}
      :gen_tcp.close(client)

      Task.await(task)

      refute Process.alive?(server_pid)
    end

    test "it should emit telemetry events as expected" do
      {:ok, collector_pid} = start_collector()
      {:ok, server_pid, _} = start_handler(Echo)
      {:ok, %{port: port}} = ThousandIsland.listener_info(server_pid)

      ThousandIsland.stop(server_pid)

      events = ThousandIsland.TelemetryCollector.get_events(collector_pid)
      assert length(events) == 2

      assert {[:listener, :start], %{port: ^port},
              %{transport_module: ThousandIsland.Transports.TCP, transport_opts: []}} =
               Enum.at(events, 0)

      assert {[:listener, :shutdown], %{}, _} = Enum.at(events, 1)
    end
  end

  describe "invalid configuration" do
    @tag capture_log: true
    test "it should error if a certificate is not found" do
      server_args = [
        port: 0,
        handler_module: Error,
        handler_options: [test_pid: self()],
        transport_module: ThousandIsland.Transports.SSL,
        transport_options: [
          certfile: Path.join(__DIR__, "./not/a/cert.pem"),
          keyfile: Path.join(__DIR__, "./not/a/key.pem"),
          alpn_preferred_protocols: ["foo"]
        ]
      ]

      {:ok, server_pid} = start_supervised({ThousandIsland, server_args})
      {:ok, %{port: port}} = ThousandIsland.listener_info(server_pid)

      {:error, _} =
        :ssl.connect('localhost', port,
          active: false,
          verify: :verify_peer,
          cacertfile: Path.join(__DIR__, "../support/ca.pem")
        )

      ThousandIsland.stop(server_pid)

      assert_received {:options, {:certfile, _, _}}
    end

    @tag capture_log: true
    test "handshake should fail if the client offers only unsupported ciphers" do
      server_args = [
        port: 0,
        handler_module: Error,
        handler_options: [test_pid: self()],
        transport_module: ThousandIsland.Transports.SSL,
        transport_options: [
          certfile: Path.join(__DIR__, "../support/cert.pem"),
          keyfile: Path.join(__DIR__, "../support/key.pem"),
          alpn_preferred_protocols: ["foo"]
        ]
      ]

      {:ok, server_pid} = start_supervised({ThousandIsland, server_args})
      {:ok, %{port: port}} = ThousandIsland.listener_info(server_pid)

      {:error, _} =
        :ssl.connect('localhost', port,
          active: false,
          verify: :verify_peer,
          cacertfile: Path.join(__DIR__, "../support/ca.pem"),
          ciphers: [
            %{cipher: :rc4_128, key_exchange: :rsa, mac: :md5, prf: :default_prf}
          ]
        )

      ThousandIsland.stop(server_pid)

      assert_received {:tls_alert, {:insufficient_security, _}}
    end
  end

  defp start_handler(handler) do
    resolved_args = [port: 0, handler_module: handler]
    {:ok, server_pid} = start_supervised({ThousandIsland, resolved_args})
    {:ok, %{port: port}} = ThousandIsland.listener_info(server_pid)
    {:ok, server_pid, port}
  end

  defp start_collector do
    start_supervised(
      {ThousandIsland.TelemetryCollector, [[:listener, :start], [:listener, :shutdown]]}
    )
  end
end
