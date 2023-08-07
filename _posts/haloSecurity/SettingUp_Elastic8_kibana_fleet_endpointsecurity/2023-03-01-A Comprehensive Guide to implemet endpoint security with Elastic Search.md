---
layout: post
title: "A Comprehensive Guide to implemet endpoint security with Elastic Search"
author: HL
categories: [Elastic Search,End Point Security]
image: /post_img/halosec/post1/elastic.png
beforetoc: "In today's digital landscape, effective log management and security monitoring are crucial for organizations to detect and respond to potential threats. Elastic Stack, with its powerful tools like Elastic 8, Kibana, Fleet, and Endpoint Security, offers a robust solution for log collection, analysis, and endpoint protection. In this blog post, we will provide a step-by-step guide to setting up Elastic 8 with Kibana, Fleet, Endpoint Security, and Windows log collection, enabling you to enhance your organization's security posture."
toc: true
published: true
tags: [SIEM,EndPointSecurity,Elastic Search,Sysmon]
description: Port 80/443 reconnaisance
---
In today's rapidly evolving digital landscape, organizations face ever-increasing security challenges. Endpoint security, which focuses on protecting individual devices such as laptops, desktops, and servers, plays a critical role in safeguarding against cyber threats. To effectively manage and secure endpoints at scale, organizations turn to powerful tools like Elastic and Fleet Management.

Elastic, renowned for its Elastic Stack, offers a comprehensive platform that enables organizations to collect, analyze, and visualize data from various sources. With its robust capabilities and scalability, Elastic is not only a popular choice for log management and search but also provides a strong foundation for endpoint security.

Fleet Management, a component of Elastic, enhances the capabilities of Elastic by providing centralized management and monitoring of endpoints. It allows organizations to streamline the deployment, configuration, and enforcement of security policies across their endpoint infrastructure. By leveraging Elastic and Fleet Management together, organizations can achieve a holistic approach to endpoint security.

In this blog post, we will explore the power of Elastic and Fleet Management in the realm of endpoint security. We will delve into the key features and benefits of using Elastic for endpoint security, along with the capabilities offered by Fleet Management. We will discuss how these tools integrate with existing security frameworks and enable organizations to detect, respond to, and prevent potential threats at the endpoint level.


### Resources 

CentOS/Ubuntu server  2x
  - 2 GB RAM 
  - 20 GB storage

Windows 10 client 
  - 2GB RAM
  - 40 GB storage 

## Elastic Search - Kibana (Cent OS server )

### Elasticsearch:
Elasticsearch is a distributed, scalable, and highly versatile search and analytics engine. It is designed to handle large volumes of data and perform lightning-fast searches across diverse data types. Elasticsearch uses a document-oriented approach, where data is stored in JSON documents and indexed for quick retrieval. It provides advanced search capabilities, including full-text search, geospatial search, and filtering. Elasticsearch is built on top of Apache Lucene, a widely-used search library.

### Kibana:
Kibana is a data visualization and exploration tool that complements Elasticsearch. It provides a user-friendly interface to interact with the data stored in Elasticsearch. With Kibana, users can create dynamic dashboards, perform ad-hoc data exploration, and generate visualizations and reports. It offers a range of visualization options such as line charts, bar charts, maps, and tables. Kibana's intuitive interface empowers users to gain insights from their data without the need for complex coding or query languages.

## Fleet Management (Cent OS server )
Fleet Management is a component of Elastic Stack that focuses on centralizing the management and monitoring of endpoints. It works in conjunction with Elasticsearch and Kibana to provide a comprehensive solution for endpoint security and management.

- Centralized Endpoint Management:

Fleet Management allows organizations to manage and monitor a large number of endpoints from a central location. It provides a unified interface within Kibana, enabling administrators to efficiently perform tasks such as configuration management, policy enforcement, and software updates across distributed endpoints.

- Agent-Based Architecture:

Fleet Management employs an agent-based architecture to facilitate communication between the central server and endpoints. The Elastic Agent, a lightweight and cross-platform agent, is installed on the endpoints to collect and transmit data securely to Elasticsearch. It streamlines the deployment and management of agents across various operating systems, making it easier to maintain a consistent security posture.

- Security Policy Enforcement:

Fleet Management enables organizations to define and enforce security policies on endpoints. Policies can include configurations for antivirus software, firewall settings, encryption requirements, and more. Administrators can create policies in Kibana and push them to the targeted endpoints, ensuring consistent security measures throughout the organization.

- Software Updates and Patch Management:

Fleet Management simplifies the process of deploying software updates and patches to endpoints. It allows administrators to schedule updates, roll them out in stages, and track the status of deployments. By maintaining up-to-date software versions on endpoints, organizations can mitigate vulnerabilities and enhance overall security.

- Monitoring and Alerting:

Fleet Management provides real-time monitoring and alerting capabilities for endpoints. It collects and analyzes endpoint data, allowing administrators to detect anomalies, monitor system performance, and identify potential security incidents. Alerts can be configured based on predefined conditions, enabling proactive response to security threats or system issues.

- Integration with Elastic Features:

Fleet Management seamlessly integrates with other features of the Elastic Stack. For example, administrators can correlate endpoint data with log data stored in Elasticsearch to gain comprehensive insights into security incidents. It also leverages Elasticsearch's powerful search capabilities to facilitate fast and efficient querying of endpoint data ./


## Configuring Elastic search in Ubuntu server 


- Import the Elasticsearch public GPG key 

```console?prompt$
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
```

![image](/post_img/halosec/post1/Pasted image 20230607083323.png)

- Install elasticseacrh

```console?prompt$
sudo apt install elasticsearch
```

![image](/post_img/halosec/post1/Pasted image 20230607083450.png)


![image](/post_img/halosec/post1/Pasted image 20230607083627.png)

```console?prompt$
The generated password for the elastic built-in superuser is : Password 

If this node should join an existing cluster, you can reconfigure this with
'/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token <token-here>'
after creating an enrollment token on your existing cluster.

You can complete the following actions at any time:

Reset the password of the elastic built-in superuser with 
'/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic'.

Generate an enrollment token for Kibana instances with 
 '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana'.

Generate an enrollment token for Elasticsearch nodes with 
'/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node'.

-------------------------------------------------------------------------------------------------

```

- As part of the installation process, an important piece of information is provided, which is the initial user. If this information is missed during installation, it can be found in the "user share elastic bin directory" under the name `elastic-password-reset.`

- In situations where the password is lost, but root access to the host is available, using the `elastic-password-reset` tool will allow for password reset. 

![image](/post_img/halosec/post1/Pasted image 20230607084229.png)



![image](/post_img/halosec/post1/Pasted image 20230607084747.png)


```console?prompt$
sudo nano /etc/elasticsearch/elasticsearch.yml
```


![image](/post_img/halosec/post1/Pasted image 20230607084923.png)


![image](/post_img/halosec/post1/Pasted image 20230607084952.png)

- To view the Elastic Search configurations in the elasticsearch.yml file, simply access the file and review its contents. In our scenario, where we plan to install Elastic Fleet Server and Elastic Search on separate machines, it is recommended to keep the configurations at their default settings. By default, Elastic Search listens on the routable interface, and it is advised to refrain from making any changes to this configuration.

> `Installing Elasticsearch and Fleet Server on separate machines offers several advantages:` 
> - isolation and Security: Running Elasticsearch and Fleet Server on separate machines enhances security and isolation. Fleet Server handles communication and coordination with agents, while Elasticsearch primarily focuses on data storage, search, and analytics. Isolating these components reduces the attack surface and potential risks.
> - Scalability: By separating Elasticsearch and Fleet Server, you can scale each component independently based on their specific resource requirements. For example, if you anticipate heavy search and indexing workloads, you can allocate more resources to Elasticsearch nodes. Similarly, if you expect high agent management and coordination needs, you can dedicate additional resources to Fleet Server.

## Install Fleet Server 

- Deploying Fleet and other components on separate machines allows for the installation of Elastic Search on a routable interface. Fleet is a service, and Elastic Search ensures that your agents remain up to date. 

- When installing Elastic Search on Windows machines, you can configure log forwarding to manage them from Elastic. This eliminates the need to access each individual box for minor changes. However, it is not desirable for all these boxes to have a direct connection back to the Elastic Search box. If any of these boxes are compromised, it would put the entire Elastic database at risk. Additionally, workstations, especially laptops, can be mobile and may connect from public places. 

- To mitigate these risks, it is recommended to install Fleet on an isolated machine. By doing so, if a workstation is compromised, it can only communicate with Fleet and is unable to access the Elastic database. This limits the amount of information that can be obtained and reduces the potential impact.

### Ensure that the Elastic Server is up and running.

```console?prompt$
curl -X GET -k https://elastic:password@localhost:9200
# curl -X GET -k https://elastic:password@localhost:9200
```

![image](/post_img/halosec/post1/Pasted image 20230607105321.png)

- We have received a response indicating that the Elastic database is up and running.

### Installing Kibana in Elastic Search server 

- Kibana serves as the user interface for Elasticsearch.

![image](/post_img/halosec/post1/Pasted image 20230607105657.png)

### Generate an enrollment token for the Kibana instance from Elasticsearch.

```console?prompt$
Generate an enrollment token for Kibana instances with 
 '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana'
```
![image](/post_img/halosec/post1/Pasted image 20230607105953.png)

- created enrollement token for kibana instance 

- enrolllemnt token of kibana 
![image](/post_img/halosec/post1/Pasted image 20230607110426.png)

- enrolling kiban with token

```console?prompt$
root@ubuntu2004:/usr/share/kibana/bin/kibana-setup
```
- start kibana service
![image](/post_img/halosec/post1/Pasted image 20230607110621.png)

```console?prompt$
root@ubuntu2004:/# systemctl start kibana
root@ubuntu2004:/# systemctl enable  kibana
Created symlink /etc/systemd/system/multi-user.target.wants/kibana.service → /lib/systemd/system/kibana.service.
root@ubuntu2004:/# systemctl start kibana
root@ubuntu2004:/# 
```
### Check the network to verify if the kiabana is up and running.

```console?prompt$
ss -lntp
# The command "ss -lntp" is used to list all listening network sockets and their corresponding processes on a Linux system. It provides information about open ports, protocols, and the programs associated with each socket.
```

![image](/post_img/halosec/post1/Pasted image 20230607110719.png)


![image](/post_img/halosec/post1/Pasted image 20230607110828.png)

- check kibana listening on the port 

![image](/post_img/halosec/post1/Pasted image 20230607111039.png)

- recommend to put nginx infront of kibana
- It doesnt have built in ssl  so better to put the apache ornginx infront of it 

#### Install nginx in Elastic server 

In NGINX, the `proxy_pass` directive is used to configure reverse proxying. It allows NGINX to act as an intermediary server that forwards client requests to backend servers and returns the response to the client.

When you define a `proxy_pass` directive in NGINX configuration, it specifies the backend server's URL where the client requests should be forwarded. NGINX acts as a proxy, accepting incoming requests from clients and passing them to the specified backend server. It can be an IP address, domain name, or even another NGINX server.

![image](/post_img/halosec/post1/Pasted image 20230607111318.png)

![image](/post_img/halosec/post1/Pasted image 20230607111553.png)

![image](/post_img/halosec/post1/Pasted image 20230607114830.png)

```console?prompt$
nano /etc/nginx/sites-enabled/default
```
![image](/post_img/halosec/post1/Pasted image 20230607112304.png)

Here's an example of how `proxy_pass` is typically used in an NGINX configuration:

```console?prompt$
location / {
    proxy_pass http://backend_server;
}
```

In this example, any request received by NGINX at the specified location (`/`) will be forwarded to the `backend_server` specified in the `proxy_pass` directive.

NGINX's `proxy_pass` directive is a powerful feature that enables load balancing, caching, and other advanced proxying capabilities. It is commonly used in scenarios where you want NGINX to handle incoming requests and route them to different backend servers based on specific rules or configurations

![image](/post_img/halosec/post1/Pasted image 20230607111827.png)

- anything hit nginx port 80 will get passed to port 5601

![image](/post_img/halosec/post1/Pasted image 20230607112349.png)

- restart and check status of nginx


![image](/post_img/halosec/post1/Pasted image 20230607133034.png)


##  Add Integrations

![image](/post_img/halosec/post1/Pasted image 20230607191735.png)

- Install fleet server 

![image](/post_img/halosec/post1/Pasted image 20230607191822.png)

- setting up default policy for default server 

![image](/post_img/halosec/post1/Pasted image 20230607191923.png)

- add a fleet server 

![image](/post_img/halosec/post1/Pasted image 20230607192023.png)

- setup new instance 

- Add fleet server 

![image](/post_img/halosec/post1/Pasted image 20230607194112.png)

- setting up fleet server with ip address 

![image](/post_img/halosec/post1/Pasted image 20230607194304.png)

![image](/post_img/halosec/post1/Pasted image 20230607194427.png)

![image](/post_img/halosec/post1/Pasted image 20230607194526.png)


### setting up SSL/TLS handshake between elastic server and fleet server 

The http_ca.crt certificate refers to the Certificate Authority (CA) certificate used for establishing trust in the HTTP communication. It is a public key certificate issued by a trusted CA that is responsible for verifying and authenticating the identities of entities involved in the communication. The http_ca.crt certificate ensures the integrity and security of the HTTPS connections by enabling the verification of the server's identity during the SSL/TLS handshake process. It is used to validate the authenticity of the server's certificate presented during the SSL/TLS negotiation.
![image](/post_img/halosec/post1/Pasted image 20230607194810.png)

- this is where all the eastic certificates are stored

![image](/post_img/halosec/post1/Pasted image 20230607194927.png)

- start an http server to transfer files 
- we need to encrypt the certificate and put there 

![image](/post_img/halosec/post1/Pasted image 20230607195109.png)

- create a folder  in following locations
- because /etc apt my  package manager modifies files there .We dont want to remove the certificates  , so we are putting in `/usr/local/etc/ssl/certs/elastic`

```console?prompt$
root@ubuntuserver2204:/etc/elasticsearch/certs# scp http_ca.crt root@192.168.0.157:/usr/local/etc/ssl/certs/elastic

The authenticity of host '192.168.0.157 (192.168.0.157)' can't be established.
ED25519 key fingerprint is SHA256:MUoW05rSrv+IqIrGlsmm8Qqo3rvrZcRevA2ArSxHSts.
This key is not known by any other names
```

![image](/post_img/halosec/post1/Pasted image 20230607202410.png)

- now we can able to install the fleet server 

```console?prompt$
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.8.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.8.0-linux-x86_64.tar.gz
cd elastic-agent-8.8.0-linux-x86_64
sudo ./elastic-agent install \
  --fleet-server-es=https://192.168.57.130:9200 \
  --fleet-server-service-token=AAEAAWVsYXN0aWMvZmxlZXQtc2VydmVyL3Rva2VuLTE2ODYzMTMxODI3NjU6UFJzcFh4ME5RakNxUmJubFRpMW9FUQ \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca-trusted-fingerprint=b7768ae54bcbe6a957ef084152bd6b492a4bab3172fda3d16b472a7fecbabdcc \
  --fleet-server-port=8220
  --fleet-server-es-ca=/usr/local/etc/ssl/certs/elastic/http_ca.crt \
  --insecure 
```

> Since we are utilizing self-assigned certificates, it is necessary to extract a certificate. Additionally, we need to include the `--insecure` flag due to the usage of self-signed certificates.

![image](/post_img/halosec/post1/Pasted image 20230607202658.png)

![image](/post_img/halosec/post1/Pasted image 20230607202931.png)

### creating policies and add agent 

![image](/post_img/halosec/post1/Pasted image 20230609135048.png)

![image](/post_img/halosec/post1/Pasted image 20230609135024.png)


### windows elastic agent installer

![image](/post_img/halosec/post1/Pasted image 20230609135147.png)

```console?prompt$
$ProgressPreference = 'SilentlyContinue' 

Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.8.0-windows-x86_64.zip -OutFile elastic-agent-8.8.0-windows-x86_64.zip 

Expand-Archive .\elastic-agent-8.8.0-windows-x86_64.zip -DestinationPath . 

cd elastic-agent-8.8.0-windows-x86_64 

.\elastic-agent.exe install --url=https://192.168.57.131:8220 --enrollment-token=U2FvMG9JZ0J1V1dXV0ppQnExbHc6WGF0RXdROWhTMWE0cnFveUJVYU5mQQ== --insecure
```

![image](/post_img/halosec/post1/Pasted image 20230609141529.png)

![image](/post_img/halosec/post1/Pasted image 20230610070424.png)

![image](/post_img/halosec/post1/Pasted image 20230610092739.png)


## Add elastic endpoint and cloud security 

![image](/post_img/halosec/post1/Pasted image 20230610194756.png)

![image](/post_img/halosec/post1/Pasted image 20230610195023.png)

![image](/post_img/halosec/post1/Pasted image 20230610211136.png)

```console?prompt$
PS C:\Program Files\Elastic\Agent> .\elastic-agent.exe status
Error: failed to communicate with Elastic Agent daemon: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing open \\\\.\\pipe\\elastic-agent-system: Access is denied."
For help, please see our troubleshooting guide at https://www.elastic.co/guide/en/fleet/8.8/fleet-troubleshooting.html
PS C:\Program Files\Elastic\Agent>
```

### Install EndPoint Security 

![image](/post_img/halosec/post1/Pasted image 20230611200734.png)

- In endpoint security, the creation of rules is essential.

![image](/post_img/halosec/post1/Pasted image 20230611200957.png)


- In the security management section, navigate to Alerts.An encrypted key for the API is required in order to download all the rules from Elastic.Therefore, proceed to create an API key.Access the Elastic box to complete the necessary steps.


- The Kibana encryption key is a crucial component used for securing security alerts in Kibana. This encryption key is used to encrypt sensitive information related to security alerts, such as the actual alert contents, user credentials, and any other confidential data associated with the alerts.

- By encrypting the security alert data, the encryption key ensures that the information remains protected and can only be accessed by authorized individuals or systems. It adds an extra layer of security to prevent unauthorized access, tampering, or exposure of sensitive alert details.

The usage of the Kibana encryption key for security alerts involves the following:

1. Encryption: When a security alert is created or stored in Kibana, the alert data is encrypted using the encryption key. This process converts the sensitive information into an unreadable format, rendering it inaccessible to unauthorized entities.

2. Decryption: When authorized users or systems need to access the security alerts, the encrypted data is decrypted using the encryption key. This allows the authorized entities to view and analyze the alert contents, ensuring the confidentiality and integrity of the information.

![image](/post_img/halosec/post1/Pasted image 20230611201232.png)

![image](/post_img/halosec/post1/Pasted image 20230611201302.png)

```console?prompt$
./kibana-encryption-keys generate
```

![image](/post_img/halosec/post1/Pasted image 20230611201351.png)

- copy the encryption key 
- go to 

```console?prompt$
vi /etc/kibana/kibana.yml
```

![image](/post_img/halosec/post1/Pasted image 20230611201458.png)
 
-  restart  kibana to make changes 

```console?prompt$
systemctl restart kibana
```


![image](/post_img/halosec/post1/Pasted image 20230611201723.png)

![image](/post_img/halosec/post1/Pasted image 20230611201751.png)

![image](/post_img/halosec/post1/Pasted image 20230611201838.png)

- then `load elastic prebulit decision rules`

![image](/post_img/halosec/post1/Pasted image 20230611202103.png)


- `select 205 rules`
- bulk actions  and enable
- some rules need machine learning to enable

> `PSEXEC rule` typically refers to a security rule or configuration specifically designed to monitor and manage the use of PsExec (PsExec.exe) within an environment. PsExec is a command-line tool developed by Microsoft Sysinternals that allows for remote execution of processes on other systems.
> The purpose of a PSEXEC rule is to control and monitor the usage of PsExec to prevent misuse, unauthorized access, or potential security risks. It enables security teams to enforce security policies and detect suspicious or malicious activities involving PsExec.

![image](/post_img/halosec/post1/Pasted image 20230611202431.png)

- this is going to collect things like sysmon logs, powershell logs etc

![image](/post_img/halosec/post1/Pasted image 20230611202554.png)

##  SSL/TLS verification 

1. To disable SSL/TLS verification when communicating with the agent machine and Elastic Search, you can follow these steps:

2. Locate the configuration file for the software or tool you are using to communicate with Elastic Search. This file may vary depending on the specific tool, so refer to the documentation or configuration files of your software.

3. Open the configuration file in a text editor.

4. Look for the SSL/TLS-related configuration options. These options may be named "ssl_verify", "tls_verify", "verify_ssl", or similar. The specific name may vary based on the tool you are using.

5. Set the value of the SSL/TLS verification option to "false" or "disable". This step will vary depending on the configuration syntax of your tool.

6. Save the changes to the configuration file

![image](/post_img/halosec/post1/Pasted image 20230611204353.png)

```console?prompt$
elastic -> endpoint -> state -> log
``` 

![image](/post_img/halosec/post1/Pasted image 20230611204530.png)

![image](/post_img/halosec/post1/Pasted image 20230611204613.png)

![image](/post_img/halosec/post1/Pasted image 20230611204650.png)

![image](/post_img/halosec/post1/Pasted image 20230611204718.png)

![image](/post_img/halosec/post1/Pasted image 20230611204824.png)

> SSL verification is disabled for Fleet.
> Now, let's proceed with querying the data in Elastic Search.
> If an attacker compromises the installed log, they can establish communication with Elastic Search. Furthermore, there is a possibility that they can extract data from it.

- Using Logstash as an intermediary between data sources and Elastic Search offers several advantages:

- Data Transformation: Logstash provides powerful data transformation capabilities. It can parse, enrich, filter, and modify data from various sources before sending it to Elastic Search. This allows you to shape and structure the data according to your requirements, ensuring it is in the desired format for efficient indexing and analysis.

- Flexibility: Logstash supports a wide range of input plugins, allowing you to collect data from diverse sources such as log files, databases, message queues, and more. It also supports multiple output plugins, giving you the flexibility to route data to different destinations beyond Elastic Search, such as other storage systems, data lakes, or external analytics tools.

- Scalability and Performance: Logstash acts as a buffer between data sources and Elastic Search. It can handle high-volume data streams efficiently by buffering and batching data before sending it to Elastic Search. This helps to alleviate the load on Elastic Search, ensuring optimal performance and scalability of the system.

- Data Enrichment: Logstash enables data enrichment by integrating with external systems or databases. It can enrich incoming data with additional information, such as geolocation data, user information, or any custom metadata, before indexing it into Elastic Search. This enrichment process enhances the context and value of the indexed data.

- Security and Access Control: Logstash can serve as a security layer by implementing access controls, authentication mechanisms, and encryption for data in transit. It provides options to secure communication channels, authenticate data sources, and apply data encryption, ensuring the confidentiality and integrity of the data being processed and indexed.

- Data Manipulation and Aggregation: Logstash offers a wide range of filter plugins that allow data manipulation and aggregation. You can perform operations like splitting, merging, joining, or aggregating data streams, enabling you to derive meaningful insights or perform complex analysis on the data before it reaches Elastic Search.

![image](/post_img/halosec/post1/Pasted image 20230611205217.png)

Logstash serves as a log forwarder, where logs are first written to Logstash and then forwarded to Elastic Search. In this process, a host will send logs to Logstash, and Logstash will subsequently forward them to Elastic Search for storage and analysis.

### steps to disable ssl/verification disable in elastic search file to get the log data from the agents 

1. Open the Elasticsearch configuration file (elasticsearch.yml) using a text editor. The file is typically located in the Elasticsearch installation directory.

2. Locate the xpack.fleet.agents.elasticsearch section in the configuration file. If it doesn't exist, you can add it at the end of the file.

3. Set the hosts parameter under xpack.fleet.agents.elasticsearch to the proper URL where the agents will send monitoring data. For example:
 
 ```console?prompt$
 xpack.fleet.agents.elasticsearch.hosts: ["http://your-elasticsearch-url:9200"]

 ```

 Replace your-elasticsearch-url with the actual URL of your Elasticsearch instance.

4. To disable SSL/TLS verification, add the following line under the xpack.fleet.agents.elasticsearch section:

```console?prompt$
xpack.fleet.agents.elasticsearch.ssl.verification_mode: none
```

This configuration will instruct the agents to skip SSL/TLS verification when communicating with Elasticsearch

5. Save the changes to the elasticsearch.yml file.

6. Restart the Elasticsearch service to apply the configuration changes.

![image](/post_img/halosec/post1/Pasted image 20230611205743.png)

![image](/post_img/halosec/post1/Pasted image 20230611205816.png)


- out put managed outside , it is a kibana setting 

```console?prompt$
vi /etc/kibana/kibana.yml
```

![image](/post_img/halosec/post1/Pasted image 20230611210022.png)


change `is_default:false` as well as `is_default_monitoring:false`

![image](/post_img/halosec/post1/Pasted image 20230611210306.png)


- `advance yamal configuration` 
```console?prompt$
ssl.verification_mode:"none"
```

![image](/post_img/halosec/post1/Pasted image 20230612072944.png)

![image](/post_img/halosec/post1/Pasted image 20230612073110.png)

- view a particular log in the data view

### Sysmon

System Monitor (Sysmon) is a powerful Windows utility provided by Microsoft that enables detailed monitoring and logging of system activity. Sysmon generates event logs with specific Event IDs (Event ID numbers) to capture various types of system events. Here are some common Sysmon Event IDs and their use cases:

1. Event ID 1: Process Creation

Use case: Captures information about new process creations, including the process name, process ID (PID), command line arguments, parent process ID (PPID), and other relevant details. Useful for monitoring suspicious process executions and tracking potential malware activity.
Event ID 2: A process changed a file creation time

Use case: Logs changes made to the creation time of files by processes. Helps identify unauthorized modifications or tampering of file attributes.

2. Event ID 3: Network connection

Use case: Records network connections established by processes, including source and destination IP addresses, ports, protocol, and other network-related information. Enables network monitoring and detection of suspicious or unauthorized network activity.

3. Event ID 7: Image Loaded

Use case: Tracks when DLL files or other executable images are loaded by processes. Helps in identifying potentially malicious code injection or unauthorized loading of modules.
Event ID 8: CreateRemoteThread

Use case: Detects attempts to create a thread in a remote process, which is a common technique used by malware for process injection. Useful for identifying malicious behavior and monitoring for unauthorized process modifications.

4. Event ID 11: FileCreate

Use case: Logs file creations, including file names, paths, and other relevant details. Helpful for tracking suspicious file creation activities and detecting potential unauthorized file generation.
Event ID 13: RegistryEvent (Registry key and value create, delete, and modify)

Use case: Monitors changes made to the Windows Registry, such as key and value creations, deletions, or modifications. Enables detection of registry-based attacks, unauthorized changes to critical registry settings, or suspicious registry modifications.

![image](/post_img/halosec/post1/Pasted image 20230612073521.png)

![image](/post_img/halosec/post1/Pasted image 20230612073601.png)

![image](/post_img/halosec/post1/Pasted image 20230612073640.png)

![image](/post_img/halosec/post1/Pasted image 20230612073735.png)


![image](/post_img/halosec/post1/Pasted image 20230612073756.png)

![image](/post_img/halosec/post1/Pasted image 20230612080230.png)

![image](/post_img/halosec/post1/Pasted image 20230612080327.png)

> Sysmon provides the capability to filter events based on the process   name. By applying a filter on the process name, you can selectively monitor and log events for specific processes of interest. This filtering feature allows you to focus on particular applications or processes that are critical to your monitoring and security requirements.


![image](/post_img/halosec/post1/Pasted image 20230612080415.png)

### Alerts 

The "Alerts" section in Elastic Security refers to a dedicated area within the Elastic Stack that focuses on monitoring and managing security alerts. It is a comprehensive feature that enables the detection, analysis, and response to security events and threats in real-time.

In the Alerts section, security analysts can configure and customize rules to define specific conditions and triggers that indicate potential security incidents. These rules can be based on various data sources and detection techniques, including network traffic analysis, log analysis, behavior analytics, and threat intelligence.

When an alert is triggered, Elastic Security provides a centralized view of all active alerts, allowing analysts to investigate and triage each alert. It presents relevant information such as the severity, source, and details of the alert, along with any supporting evidence or context.

Furthermore, Elastic Security offers a wide range of built-in integrations and automation capabilities to facilitate incident response. Analysts can take actions directly from the Alerts section, such as quarantining a compromised endpoint, blocking an IP address, or launching an investigation workflow.

The Alerts section in Elastic Security is designed to enhance the detection and response capabilities of security operations teams, providing a centralized platform for managing and responding to security incidents efficiently and effectively.

![image](/post_img/halosec/post1/Pasted image 20230612080518.png)

![image](/post_img/halosec/post1/Pasted image 20230612080612.png)

- It provides us with a graphical representation of all the background processes that have been initiated, displaying the progress of each badge. 

![image](/post_img/halosec/post1/Pasted image 20230612080651.png)


## Conclusion


In conclusion, we have successfully developed a SIEM (Security Information and Event Management) solution using Elasticsearch and Fleet Server. Throughout the process, we disabled SSL/TLS verification to simplify the configuration and ensure seamless communication between the components.

By leveraging Elasticsearch, we established a robust and scalable backend for log storage, analysis, and search capabilities. The combination of Elasticsearch's powerful indexing and querying capabilities with Fleet Server's management features allowed us to efficiently handle log data from multiple agents.

Although we disabled SSL/TLS verification for convenience, it's important to note the security implications. Disabling SSL/TLS verification removes the encryption layer and exposes the communication to potential risks. Therefore, it is crucial to carefully assess the environment and implement appropriate security measures to mitigate any vulnerabilities.

By integrating Fleet Server into the SIEM architecture, we achieved centralized log management, agent configuration management, and the ability to push updates and rules to agents efficiently. This streamlined the management process and reduced the need for manual intervention on individual agent machines.

In summary, our SIEM development using Elasticsearch and Fleet Server has allowed us to build a powerful and scalable solution for log management and security monitoring. While the decision to disable SSL/TLS verification simplified the setup, it's crucial to ensure the overall security posture of the system through other means. With this SIEM solution in place, we can effectively analyze and respond to security events, enhancing the overall security posture of the organization.


## References

1. https://youtu.be/Ts-ofIVRMo4 - Setting Up Elastic 8 with Kibana, Fleet, Endpoint Security, and Windows Log Collection

2. https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elastic-stack-on-ubuntu-22-04

3. https://youtu.be/wiQ8U5mFncw - How To Setup ELK | Elastic Agents & Sysmon for Cybersecurity
