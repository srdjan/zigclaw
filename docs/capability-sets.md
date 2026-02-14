# Capability Sets

A capability set is a named profile that drives:
- which tools/plugins may run
- whether network is allowed (primarily for core providers; tools are typically no-network)
- which paths may be mounted as read-write into WASI plugins

This provides a data-driven, auditable control plane over agent autonomy.
