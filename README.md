# Generating, Capturing, and Analyzing DoS and DDoS-centric Network Traffic

This project focuses on understanding, simulating, and analyzing network traffic generated during Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks. The practical exercises aim to provide insights into detecting and mitigating these types of network-based threats.

---

## Objectives

- **Simulate DoS and DDoS attacks** using various tools and techniques.
- **Capture and analyze network traffic** during these attacks using network monitoring tools.
- **Identify key characteristics** of DoS and DDoS traffic.
- **Evaluate mitigation strategies** to defend against such attacks.

---

## Tools Used

- **Wireshark**: For packet analysis and capturing network traffic.
- **Nmap**: To scan and map networks during simulated attacks.
- **Hping3**: For crafting and sending custom packets.
- **LOIC/HOIC**: Simulating DoS and DDoS attacks in a controlled environment.
- **Snort**: For intrusion detection and alert generation.

---

## Key Steps

1. **Setup and Configuration**:
   - Configure the network environment to safely simulate attacks without impacting production systems.
   - Ensure all tools are installed and tested for functionality.

2. **Generating Traffic**:
   - Use tools like Hping3 and LOIC to generate DoS and DDoS traffic.
   - Simulate various types of attacks such as SYN floods, UDP floods, and HTTP GET floods.

3. **Capturing Traffic**:
   - Use Wireshark to monitor and capture packets during the attack simulations.
   - Save captured traffic in `.pcap` files for analysis.

4. **Analyzing Traffic**:
   - Identify patterns such as high packet rates, source IP spoofing, and unusual port activity.
   - Use Snort to analyze alerts generated during the simulation.

5. **Mitigation Testing**:
   - Apply techniques like rate limiting, IP filtering, and use of Web Application Firewalls (WAF).
   - Measure the effectiveness of each mitigation strategy.

---

## Results

- Identified common traits of DoS and DDoS traffic, such as:
  - High packet volume in a short duration.
  - Repeated SYN requests without completing the TCP handshake.
  - Distributed sources in DDoS scenarios.
- Demonstrated the importance of network monitoring tools in identifying and mitigating attacks.

---

## Project Resources

- **Project Link**: [Generating, Capturing, and Analyzing DoS and DDoS-centric Network Traffic](https://github.com/StephVergil/Generating-capturing-and-Analyzing-DoS-and-DDoS-centric-Network-Traffic/blob/main/vNetLab3%20Lab%205.docx.pdf)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Snort Rules Documentation](https://snort.org/documents)
- [Understanding DDoS Attacks](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/)

---

## Conclusion

This project highlights the necessity of proactive network security measures to prevent and mitigate the impact of DoS and DDoS attacks. By simulating real-world attack scenarios, the analysis provides valuable insights into effective detection and defense mechanisms.

---

## Disclaimer

All simulations were performed in a controlled environment. Unauthorized use of these tools or techniques outside a controlled lab setup may violate laws and ethical guidelines. Ensure proper permissions are obtained for any testing.
