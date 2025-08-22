<h1>Pinaka-RAT</h1> 
RAT developed in python for Windows OS to perform red-teaming excercises to define the extent of vulnerabvility.

## Objective  
This project focuses on understanding and simulating adversary techniques in a **controlled, isolated lab environment** to improve blue-team detection and incident response capabilities. The aim was to design a proof-of-concept endpoint control and monitoring framework to explore concepts like command-and-control (C2) communication, data collection, and automation.  

By developing this project, I gained insights into how attackers interact with systems, and more importantly, how defenders can detect, respond, and mitigate such activity. **This project was purely academic and ethical, built for research and skill development.**  

---

## Skills Learned  

- **C2 and Endpoint Management Concepts**: Built a Python-based client-server model to simulate remote endpoint interaction.  
- **Secure Communication**: Implemented encryption (Fernet) for data integrity and confidentiality between endpoints and the controller.  
- **Incident Response Awareness**: Documented attacker behaviors and mapped them to detection use cases for SOC analysts.  
- **Automation & Scripting**: Automated data collection and response tasks to simulate real-world red team workflows.  
- **Defensive Mindset**: Identified opportunities to strengthen detection rules and endpoint protections.  

---

## Tools Used  

<div>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
    <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" />
    <img src="https://img.shields.io/badge/Fernet_Encryption-4CAF50?style=for-the-badge" />
    <img src="https://img.shields.io/badge/VMware_Lab-607078?style=for-the-badge&logo=vmware&logoColor=white" />
    <img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" />
</div>  

---

## Steps  

1. **Lab Setup**  
   - Configured an isolated network with multiple Windows and Linux virtual machines using VMware to ensure safe testing.  
   - Prepared endpoints to simulate target systems and a controller to manage operations.  

2. **Design & Development**  
   - Built a lightweight backend using Flask to handle encrypted communications.  
   - Developed a Python client capable of executing predefined tasks (system information gathering, file retrieval) strictly for simulation.  

3. **Secure Communication**  
   - Implemented Fernet encryption to ensure data exchanged between client and server remained confidential and tamper-proof.  
   - Tested message integrity and key management concepts.  

4. **Testing & Analysis**  
   - Generated test commands and observed endpoint responses.  
   - Captured logs and telemetry to evaluate detection potential.  

5. **Defensive Applications**  
   - Mapped actions to MITRE ATT&CK techniques.  
   - Suggested SOC playbooks and alerts based on observed behaviors to improve detection strategies.  

---

## Example Screenshots  

*(Add your screenshots here with short explanations, for example)*  

- **Ref 1: Lab Network Diagram**  
- **Ref 2: Flask Backend Running in Test Environment**  
- **Ref 3: Endpoint Responding to a Simulated Command**  

---

## Key Takeaways  

- Learned how endpoint management and attacker simulations work in a contained lab environment.  
- Strengthened understanding of encryption, logging, and data flow.  
- Gained confidence in translating offensive knowledge into defensive detection measures.  

---

### Next Steps  

- Expand the lab to include SIEM integration for real-time alerting.  
- Add automation workflows using SOAR tools for incident triage.  
- Conduct further research into adversary techniques for proactive defense.  
