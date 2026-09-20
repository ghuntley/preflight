{ pkgs, module, package }:
pkgs.testers.runNixOSTest {
  name = "preflight";
  nodes.machine = { ... }: {
    imports = [ module ];
    services.preflight.enable = true;
    services.preflight.package = package;
    services.preflight.mode = "no-go";
    systemd.services.mock-underclass = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig.ExecStart = "${package}/bin/preflight-worker /tmp mock";
    };
    environment.systemPackages = [ pkgs.curl package ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("preflight.service")
    machine.wait_for_unit("mock-underclass.service")
    machine.wait_for_open_port(8081)
    machine.wait_for_open_port(8080)
    machine.succeed("curl --fail http://127.0.0.1:8081/readyz")
    machine.succeed("test $(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{invalid' http://127.0.0.1:8081/v1/responses) = 400")
    machine.succeed("${package}/bin/preflight-worker /tmp/fixtures fixtures")
    for fixture in ["clean-png", "clean-pdf"]:
        machine.succeed(f"test $(curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json' --data-binary @/tmp/fixtures/{fixture}.json http://127.0.0.1:8081/v1/responses) = 200")
    for fixture in ["secret-png", "secret-pdf"]:
        machine.succeed(f"test $(curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json' --data-binary @/tmp/fixtures/{fixture}.json http://127.0.0.1:8081/v1/responses) = 409")
    machine.succeed("preflight cache purge --socket /run/preflight/control.sock")
  '';
}
