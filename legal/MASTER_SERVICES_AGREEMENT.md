# MASTER SERVICES AGREEMENT (MSA)
### ROBOTICS CYBER COMPLIANCE PLATFORM

**THIS MASTER SERVICES AGREEMENT ("AGREEMENT") GOVERNS CUSTOMER’S USE OF THE CYBER COMPLIANCE SOFTWARE AND SERVICES. BY ENROLLING ANY DEVICE, EXECUTING AN ORDER FORM, OR CLICKING TO ACCEPT, CUSTOMER AGREES TO ALL TERMS HEREIN.**

---

### 1. DEFINITIONS AND SCOPE OF SERVICE
1.1. **"Platform" or "Service"** means Provider’s automated security posture monitoring, device compliance inspection, and evidence-gathering software, including local agents (`systemd`, CLI, background daemons) and the central management interface.  
1.2. **"Customer Systems"** means physical robotics hardware, embedded single-board computers (IPCs), edge nodes, cloud infrastructure, and employee workstations enrolled into the Service.  
1.3. **"Software-Only Role"**: Provider is strictly a software provider. Provider is **NOT** a certified public accounting (CPA) firm, registered audit firm, or regulatory authority.

---

### 2. STRICT DISCLAIMER OF AUDIT GUARANTEES
2.1. **No Guarantee of Audit Outcome**: Customer acknowledges that the Platform is a continuous evidence-collection and workflow management tool. Provider makes **NO WARRANTY, EXPRESS OR IMPLIED, THAT CUSTOMER WILL PASS OR ACHIEVE SOC 2 (TYPE 1 OR TYPE 2), ISO 27001, OR ANY REGULATORY AUDIT OR CERTIFICATION.**  
2.2. **Independent Auditor Discretion**: All audit determinations, certifications, and compliance evaluations are made solely and independently by Customer's chosen third-party licensed CPA firm or accredited registrar. Provider bears zero legal or financial responsibility for audit failure, auditor findings, or delayed certifications.

---

### 3. CYBERSECURITY AND BREACH DISCLAIMER
3.1. **No Warranty of Immunity**: Continuous compliance monitoring does not guarantee immunity from security vulnerabilities, zero-day exploits, unauthorized intrusions, social engineering, or cyberattacks.  
3.2. **Zero Breach Liability**: IN NO EVENT SHALL PROVIDER BE LIABLE FOR ANY SECURITY INCIDENTS, RANSOMWARE, DATA BREACHES, UNAUTHORIZED SYSTEM ACCESS, OR DATA COMPROMISE AFFECTING CUSTOMER SYSTEMS.

---

### 4. ROBOTICS HARDWARE & OPERATIONAL SAFETY WAIVER
4.1. **Physical and Embedded Constraints**: Customer acknowledges that agents and monitoring scripts operate in complex embedded environments (including ROS, ROS 2, real-time kernels, CAN bus networks, and autonomous field robots).  
4.2. **Operational Disclaimers**: PROVIDER EXPRESSLY DISCLAIMS ANY LIABILITY FOR:
- Device lockouts, system crashes, or hardware bricking.
- Network interface drops, latency spikes, or cellular telemetry disconnects.
- Interruption of real-time control loops, motor actuation, or sensor pipelines.
- Physical injury, property damage, or operational downtime resulting from running the agent or implementing suggested remediations.  
4.3. **Customer Discretion**: Any remediation actions, firewall rules, port closures, or configuration scripts executed by Customer are undertaken solely at Customer’s own risk and discretion.

---

### 5. ZERO-PAYLOAD DATA PRIVACY COMMITMENT
5.1. **Zero-Payload Boundary**: Provider agrees that the Platform is engineered strictly to inspect system security metadata (e.g. firewall active status, open listening port numbers, OS version strings, cryptographic hashes).  
5.2. **Prohibited Ingestion**: Provider’s agents shall **never** record, ingest, or transmit:
- Camera video streams or visual imagery.
- LiDAR point clouds or SLAM facility maps.
- ROS message payloads or customer sensor streams.
- Customer proprietary application source code.

---

### 6. LIMITATION OF LIABILITY
6.1. **LIABILITY CAP**: TO THE MAXIMUM EXTENT PERMITTED BY LAW, PROVIDER’S ENTIRE AGGREGATE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT, WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE, **SHALL NOT EXCEED THE TOTAL FEES ACTUALLY PAID BY CUSTOMER TO PROVIDER IN THE TWELVE (12) MONTHS PRECEDING THE CLAIM.**  
6.2. **CONSEQUENTIAL DAMAGES WAIVER**: IN NO EVENT SHALL PROVIDER BE LIABLE FOR ANY INDIRECT, SPECIAL, INCIDENTAL, PUNITIVE, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING LOSS OF PROFITS, LOSS OF REVENUE, BUSINESS INTERRUPTION, ROBOT DOWNTIME, OR LOSS OF DATA), EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

---

### 7. GOVERNING LAW AND DISPUTE RESOLUTION
This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware, without regard to conflict of law principles. Any dispute arising out of this Agreement shall be resolved through binding arbitration administered by JAMS.
