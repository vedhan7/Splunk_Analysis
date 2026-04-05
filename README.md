# Analyzing Failed Login Attempts using Linux Auth Logs with Splunk

## 📌 Project Overview
This project focuses on enhancing system security by leveraging **Splunk Enterprise** to monitor and analyze Linux authentication logs (`auth.log`). The primary goal is to detect unauthorized access attempts, specifically SSH brute-force attacks, by tracking failed login events. 

By ingesting these logs into Splunk, writing specific Search Processing Language (SPL) queries, and creating visual dashboards, this project demonstrates how Security Information and Event Management (SIEM) tools can be used to identify malicious IP addresses, targeted usernames, and attack patterns in real time.

## 🛠️ Tools & Technologies
* **SIEM Platform:** Splunk Enterprise
* **OS Environment:** macOS (analyzing simulated Linux log data)
* **Log Data:** Linux `auth.log` (SSH authentication logs)
* **Query Language:** Splunk SPL (Search Processing Language)

## 🚀 Objectives
1. Ingest Linux authentication log data into a Splunk instance.
2. Parse unstructured syslog data to extract critical fields: `Source IP` and `Target Username`.
3. Formulate SPL queries to filter and aggregate failed password attempts.
4. Design an interactive dashboard visualizing brute-force attack patterns.

## 📊 Dashboards & Visualizations
*(Below are the results from the Splunk Dashboard)*

##Splunk Dashboard


<img width="1470" height="956" alt="splunk_dashboard" src="https://github.com/user-attachments/assets/c7342a17-83be-472b-a27f-e2743598641a" />


##Splunk Auth Log Data


<img width="1470" height="956" alt="splunk_data" src="https://github.com/user-attachments/assets/5b7d7332-3678-4084-a048-a9048e501dba" />


###Top Attacking IPs - Splunk SQL Query

source="*auth.log" "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | top src_ip

###IP - Query

source="*auth.log" "Failed password" | rex "Failed password for (?:invalid user )?(?<username>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | table _time, username, src_ip

###Top Targeted Usernames - Query

source="*auth.log" "Failed password" | rex "Failed password for (?:invalid user )?(?<username>\S+)" | top username

<img width="1470" height="956" alt="splunk2_bar" src="https://github.com/user-attachments/assets/e492d1ac-1e6a-4feb-aab9-38a32f13434e" />

### Top Attacking IPs & Targeted Usernames

<img width="1470" height="956" alt="splunkresult_dashboard" src="https://github.com/user-attachments/assets/944555b2-1f29-45c4-8445-904eb3b9ed0c" />

### Extracted All Data 
<img width="1470" height="956" alt="splunk_result" src="https://github.com/user-attachments/assets/f0bbc4d4-9805-4705-9c46-29bb64e53292" />
<img width="1470" height="956" alt="splunk_ip_visual" src="https://github.com/user-attachments/assets/0821f33b-62da-4181-a5cb-93901b3ff427" />
<img width="1470" height="956" alt="splunk_ip_result" src="https://github.com/user-attachments/assets/0eeb6c6f-6907-4e85-a038-94ac9c80f55c" />
<img width="1470" height="956" alt="splunk_data" src="https://github.com/user-attachments/assets/6a62dc47-5edd-4574-bcf4-b287800f4e41" />
<img width="1470" height="956" alt="splunk_dashboard" src="https://github.com/user-attachments/assets/786b2643-33f2-4806-b9cb-af2acd9b7dd0" />


## 🔍 Splunk SPL Queries Used

**1. Extracting Failed Logins (IPs and Usernames)**
```splunk
source="*auth.log" "Failed password" 
| rex "Failed password for (?:invalid user )?(?<username>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, username, src_ip



Finding Top Attacking IPs (For Column Chart)

source="*auth.log" "Failed password" 
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" 
| top src_ip

Finding Most Targeted Usernames (For Bar Chart)

source="*auth.log" "Failed password" 
| rex "Failed password for (?:invalid user )?(?<username>\S+)" 
| top username


👨‍💻 Author

Vedhan S 
