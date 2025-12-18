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

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Objectives](#objectives)
3. [Proposed Features](#proposed-features)
4. [Tools and Technologies](#tools-and-technologies)
5. [Project Structure](#project-structure)
6. [Execution Workflow](#execution-workflow)
7. [Architecture Diagram](#diagram)
8. [Future Work](#future-work)
9. [Usage](#usage)

## Problem Statement
Organizations create a significant amount of data related to security events from various sources, including Endpoint Devices, Network Monitoring Software, and Logs. Manually reviewing all of this information in order to identify abnormalities, connect associated pieces of data, and take action (e.g., create alerts) is a very labor-intensive process, leading to the following issues:

--> Longer to identify possible threats

--> More time needed to react to an incident

--> Additional workload on Security Operations Center personnel

--> Greater likelihood that an attack will go undetected

The proposed solution is a simple, quick, and automated means of collecting, logging, and monitoring incidents, determining what constitutes a "common" security event, and then taking the appropriate response steps with little or no manual interference.

## Objectives
The goal of the project is to:
1. Automate the detection of Security Event from System Logs.
2. Assign a severity level to incidents so they can be prioritized.
3. Keep a structured incident response workflow with timestamps.
4. Perform preliminary containment actions automatically.
5. Reduce the manual workload and improve the response time.


## Proposed Features
*Event Detection Logic:*
- Monitor System Logs for suspicious activity.
- Detect failed logins or unauthorized users, privileges elevated, unusual processes running on    the network, network anomalies, and malicious files added to your system.
- Assign a severity level of low, medium, or high.

*Incident Response Workflow:*
- Track an incident’s journey from detection to analysis to containment to recovery using a timestamp for each phase of the workflow. (Detection → Analysis → Containment → Recovery)

*Store Incidents:*
- Store Incidents in an SQLite Database, called ``incidents.db``, which will log the type of event that occurred, the severity level of the incident, the time it occurred, and the system that was compromised.

*Basic Containment Actions:*
 - Provide notification for High Severity incident through the console or the ``alerts.txt`` file.
- Future enhancement will include blocking and/or terminating processes based on the severity level of a particular incident.

*Severity Based Alert Notification System (Optional enhancement):*
- Provide notification to the Admins of High Severity Events.
- This will assist SOC Analysts in prioritizing incidents that are Critical to the organization.

*Automated Evidence Collection Folder (Optional enhancement):*
- Create an Evidence Collection Folder for each incident, including logs, system information, and metadata so that all evidence is available in a structured format for further analysis and reporting.
 
## Tools and Technologies
Python 3 – main programming language
SQLite – incident storage
VS Code / Terminal – development environment
Matplotlib (optional) – for visualization
Email / local notification system – for alerts
File system operations – Python ``os`` and ``shutil`` modules
Log sources – Linux system logs (``auth.log``, ``syslog``) or simulated logs

## Project Structure
IR-ATS/

│── main.py

│── modules/

│       ├── detection.py

│       ├── severity.py

│       ├── response.py

│       ├── storage.py

│       ├── evidence.py

│── logs/

│       └── security.log

│── evidence/

│── config/

│       └── rules.json

│── incidents.db

│── alerts.txt

## Execution Workflow
1. Start the program → python ``main.py``
2. Detection → Parse logs for suspicious events
3. Severity assignment → Determine Low, Medium, High severity
4. Storage → Insert incidents into ``incidents.db``
5. Evidence collection → Create a folder for each incident with ``log.txt`` and ``metadata.txt``
6. Alerts → Trigger console/log notifications for high-severity events
7. Output → Console print, ``alerts.txt``, evidence folders, database records

## Diagram
[Logs / Security Events] --> [Detection Engine] --> [Severity Assignment]
                                         |                 
                                         v
                              [Incident Storage (SQLite)]
                                         |
                                         v
                        [Evidence Collection + Metadata Folder]
                                         |
                                         v
                             [Alerts / Notifications]

Flow Description:

Logs: Input from system logs or simulated logs

Detection Engine: Detects suspicious events

Severity Assignment: Categorizes events as Low, Medium, or High

Incident Storage: Stores all events in SQLite database

Evidence Collection: Automatically saves logs and metadata per incident

Alerts: Notifies admin of high-severity incidents

## Future Work
1. The ability to perform live monitoring of Windows Event Logs in real-time

2. The opportunity to perform legitimate actions of containment: block an IP address; terminate malicious processes; isolate infected files

3. Make the SOC Monitoring Dashboard easier to navigate and provide better visualization of events

4. Add automated email notifications for priority incidents
   
## Usage
1. Clone the repository:
``git clone <the-link-of-repo>``
2. Ensure Python3 is installed.
3. Place a simulated or linux log file in ``logs/security.log``
4. Run the program:
   ``python main.py``
5. Check outputs:
   Database: ``incidents.db`` contains all recorded events

   Evidence: ``evidence/`` folder contains incident-specific metadata and logs

   Alerts: ``alerts.txt`` and console output for high-severity events
