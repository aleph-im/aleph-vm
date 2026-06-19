"""Shared contract between the Aleph agent and the supervisor.

This package holds the wire/interface vocabulary both sides depend on: the
``Supervisor`` ABC, the value types (``VmId``, ``VmInfo``, ``CreateVmSpec``, ...),
the closed ``SupervisorError`` enum, and the on-disk controller config-file
schema. It must not import the agent (``orchestrator``) or the supervisor
implementation (``supervisor``); both of those import *it*.
"""
