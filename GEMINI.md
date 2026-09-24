# AGY Assistant Rules & Project Context

## User Preferences
- **Thorough Code Explanations**: Always explain all code, architecture decisions, and logic thoroughly. The user wants to understand all code and follow it very closely. Do not make silent or unexplained changes.

## Project Context: Cyber Compliance for Robotics Fleets
- **Mission**: Vertical B2B compliance SaaS competing with Drata/Vanta, specifically targeting robotics and hardware startups (Seed to Series A/B).
- **Core Problem Solved**: Traditional MDM/compliance tools break Linux developer environments and completely ignore robot fleets (NixOS, ROS/ROS 2, Ubuntu edge nodes). This platform automates continuous SOC 2 evidence collection for both.
- **Architectural Tenets**:
  1. **Zero External Dependencies**: The client agent (`agent/`) and core server (`server/`) use Python standard library only (`urllib.request`, `http.server`, `sqlite3`). No complex pip setups required for edge devices.
  2. **Zero-Payload Data Policy**: Only collect security metadata (firewalls, listening port numbers, OS versions, cryptographic hashes). Never inspect, capture, or transmit camera video, LiDAR point clouds, SLAM maps, or customer proprietary code.
  3. **Strict Liability Insulation**: Pure software provider model. All contracts must include the 12-month fee liability cap, robotics hardware disruption waivers, and audit outcome disclaimers ([legal/MASTER_SERVICES_AGREEMENT.md](file:///home/alden/cyber_compliance/legal/MASTER_SERVICES_AGREEMENT.md)). Independent CPAs certify audits, not this software.
