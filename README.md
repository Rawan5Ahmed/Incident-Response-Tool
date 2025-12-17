# Incident-Response-Tool
**Overview**
An open-source project that is designed to simulate a Security Operations Center (SOC) in the form of an automated incident response solution built using the Python programming language. The primary goal behind this project is to enable Incident Responders, as well as students and hobbyists, to learn how to effectively and efficiently monitor for, triage and respond to cyber threats via a simulated SOC workflow.
*The tool analyzes system logs (simulated or Linux logs) and automatically*
→ Detection of suspicious activity including but not limited to Failed Logins, Privilege Escalation,Unauthorized User Creation, Unusual Processes, Network Anomalies, and Malicious Files.
→ Classification of event severity (low, medium, high) based on potential impact.
→ Storage of events in an organized (SQLite) structured database with timestamps to ensure accurate event tracking.
→ Automatic collection of evidence for each event (including logs, system meta-data, running processes and network connections) in a dedicated folder.
→ Notification of high severity incidents to facilitate prompt incident response.

*Table of Contents*:
1. [Problem Statement](#problem-statement)
2. [Objectives](#objectives)
3. [Problem Statement](#Proposed-Features)
4. Tools and Technologies
5. Project Structure
6. Execution Workflow
7. Diagram
8. Futute Work
9. Usage
