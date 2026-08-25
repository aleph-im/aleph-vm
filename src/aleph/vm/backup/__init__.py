"""VM disk backups.

The agent owns the archives: it created the VM's disks, so it is the side
that copies, stores, expires and restores them (``aleph.vm.agent.vm.backup``).
This package holds the parts that are pure disk and archive work, neutral
between the agent and the supervisor:

- ``archive``: the ``qemu-img`` seam and the tar + sha256 + meta.json
  archive format.
- ``staging``: the backup directory and the restore staging helpers.
- ``types``: the ``BackupInfo`` record and the backup errors.

The supervisor's only part in a backup is quiescence (``FreezeGuest`` /
``ThawGuest`` over the QEMU guest agent); it never touches an archive.
"""
