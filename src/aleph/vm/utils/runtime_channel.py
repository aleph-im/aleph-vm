"""The Aleph runtime's guest-channel conventions.

Client-side vocabulary: the supervisor contract only carries an opaque
channel (CreateVmRequest.guest_channel / VmInfo.guest_channel_path); what is
spoken over it — and on which port — is defined here, by the agent, to match
the init shipped in the Aleph runtimes.
"""

# The runtime's control port: the guest init signals readiness by connecting
# to it (host side: `<channel>_<port>`), and serves the configuration push and
# code execution on it (host dials `CONNECT <port>`).
RUNTIME_CONTROL_PORT = 52

# The guest API: an agent-owned HTTP server the program calls, bound on the
# host at `<channel>_<port>`.
GUEST_API_PORT = 53
