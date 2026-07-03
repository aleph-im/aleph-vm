"""Wire-level pieces of the Supervisor contract.

Everything the gRPC transport needs on BOTH sides of the boundary lives
here: the generated protobuf bindings (``_pb``), the DTO <-> protobuf
mapping (``proto_convert``), and the wire constants shared by the client
and the server. The supervisor daemon serves this protocol; the agent's
``aleph.vm.supervisor_interface.client.GrpcSupervisor`` consumes it.
Nothing in this package may import the agent or the supervisor.
"""

# Metadata key of the binary ErrorDetail trailer the server attaches to an
# abort so the client can rebuild the precise SupervisorError subclass.
ERROR_TRAILER_KEY = "aleph-supervisor-error-bin"
