# Incident-Response-Tool
**Overview**
An open-source project that is designed to simulate a Security Operations Center (SOC) in the form of an automated incident response solution built using the Python programming language. The primary goal behind this project is to enable Incident Responders, as well as students and hobbyists, to learn how to effectively and efficiently monitor 
for, triage and respond to cyber threats via a simulated SOC workflow.

*The tool analyzes system logs (simulated or Linux logs) and automatically*
→ Detection of suspicious activity including but not limited to Failed Logins, Privilege Escalation,Unauthorized User Creation, Unusual Processes, Network Anomalies, and Malicious Files.

→ Classification of event severity (low, medium, high) based on potential impact.

→ Storage of events in an organized (SQLite) structured database with timestamps to ensure accurate event tracking.

→ Automatic collection of evidence for each event (including logs, system meta-data, running processes and network connections) in a dedicated folder.

→ Notification of high severity incidents to facilitate prompt incident response.

*Table of Contents*
1. [Problem Statement](#problem-statement)
2. [Objectives](#objectives)
3. [Proposed Features](#proposed-features)
4. [Tools and Technologies](#tools-and-technologies)
5. [Project Structure](#project-structure)
6. [Execution Workflow](#execution-workflow)
7. [Architecture Diagram](#diagram)
8. [Future Work](#future-work)
9. [Usage](#usage--demo)

Problem Statement
Organizations create a significant amount of data related to security events from various sources, including Endpoint Devices, Network Monitoring Software, and Logs. Manually reviewing all of this information in order to identify abnormalities, connect associated pieces of data, and take action (e.g., create alerts) is a very labor-intensive process, leading to the following issues:
--> Longer to identify possible threats
--> More time needed to react to an incident
--> Additional workload on Security Operations Center personnel
--> Greater likelihood that an attack will go undetected

The proposed solution is a simple, quick, and automated means of collecting, logging, and monitoring incidents, determining what constitutes a "common" security event, and then taking the appropriate response steps with little or no manual interference.

*Objectives*
The goal of the project is to:
1. Automate the detection of Security Event from System Logs.
2. Assign a severity level to incidents so they can be prioritized.
3. Keep a structured incident response workflow with timestamps.
4. Perform preliminary containment actions automatically.
5. Reduce the manual workload and improve the response time.


*Proposed Features*
** Event Detection Logic:**

*Tools and Technologies*
*Project Structure*
*Execution Workflow*
*Diagram*
*Future Work*
*Usage*
