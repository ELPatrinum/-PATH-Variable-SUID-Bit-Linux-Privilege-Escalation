As a SOC analyst, understanding **Linux Privilege Escalation** techniques like **manipulating the PATH variable** and exploiting the **SUID bit** is critical for identifying, detecting, and mitigating potential attacks. Here’s a breakdown:

---

### **1. Privilege Escalation via PATH Variable**

### **What It Is:**

- The `$PATH` environment variable specifies directories where the system looks for executable files when a command is run without specifying its absolute path.
- Misconfigurations or unsafe modifications to `$PATH` can allow attackers to execute malicious code by tricking the system into running a malicious executable instead of the intended program.

### **How It Works:**

1. **Insecure PATH Order:**
    - If `/tmp` or other writable directories are included early in the `$PATH`, an attacker can place a malicious script or binary with the same name as a system command.
    - Example:
        
        ```bash
        echo '/bin/bash' > /tmp/ls
        chmod +x /tmp/ls
        export PATH="/tmp:$PATH"
        ls  # Executes /tmp/ls instead of /bin/ls
        ```
        
2. **Exploiting sudo with PATH:**
    - If a `sudo` command allows executing a script or binary that does not use absolute paths for commands, an attacker can manipulate `$PATH`.
    - Example:
        
        ```bash
        export PATH="/tmp:$PATH"
        echo "echo 'root compromise'" > /tmp/id
        chmod +x /tmp/id
        sudo id  # Executes /tmp/id instead of /usr/bin/id
        ```
        

### **Detection and Prevention:**

- **Monitoring:**
    - Look for unusual modifications to the `$PATH` variable.
    - Detect execution of binaries from writable or suspicious directories like `/tmp`.
- **Use Absolute Paths in Scripts and Binaries**
    
    **Why?**
    
    Using absolute paths ensures that the system executes the intended command from the correct location, regardless of the `$PATH` content.
    
    **How?**
    
    - **Modify Scripts:**
    - Replace commands like `ls`, `cp`, `echo`, etc., with their absolute paths (e.g., `/bin/ls`, `/bin/cp`, `/bin/echo`).
    - Example of an unsafe script:
        
        ```bash
        # Unsafe
        cp file.txt /backup/
        ```
        
    - Safe version:
        
        ```bash
        # Safe
        /bin/cp file.txt /backup/
        ```
        
    - **In Compiled Programs:**
        - Use full paths in system calls.
        - Example in C:
        
        ```c
        // Unsafe
        system("ls");
        // Safe
        system("/bin/ls");
        ```
        
    - **Test Scripts/Binaries:**
        - Run scripts and binaries in controlled environments to ensure all commands use absolute paths.

---

- **Restrict Write Permissions on Directories in the `$PATH`**
    
    **Why?**
    
    Writable directories in `$PATH` allow attackers to replace or add malicious binaries.
    
    **How?**
    
    1. **Find Writable Directories in `$PATH`:**
        - Check current `$PATH`:
            
            ```bash
            echo $PATH
            ```
            
        - List permissions of directories in `$PATH`:
            
            ```bash
            IFS=: read -ra dirs <<< "$PATH"
            for dir in "${dirs[@]}"; do
                ls -ld "$dir"
            done
            ```
            
    2. **Restrict Permissions:**
        - Ensure that only the root or intended users have write access to system directories in `$PATH`.
        - Example:
            
            ```bash
            chmod 755 /usr/local/bin
            chmod 755 /bin
            ```
            
    3. **Avoid Writable Directories in `$PATH`:**
        - Remove directories like `/tmp` or user-specific directories from `$PATH`:
            
            ```bash
            export PATH=$(echo $PATH | sed -e 's/:\/tmp//g')
            ```
            
    4. **Enforce with Policies:**
        - Use Access Control Lists (ACLs) to restrict directory modifications.
        - Example:
            
            ```bash
            setfacl -m u:username:r-x /usr/local/bin
            ```
            

---

- **Validate `$PATH` Content in Secure Environments**
    
    **Why?**
    
    Validating `$PATH` ensures that no malicious or unsafe directories are present.
    
    **How?**
    
    1. **Check for Dangerous Entries:**
        - Look for entries like `/tmp`, `.` (current directory), or empty entries (`::`).
        - Example:
        
        ```bash
        echo $PATH | grep -E '(^|:)(\.|/tmp|::)($|:)'
        ```
        
    2. **Set a Safe Default PATH:**
        - For critical users (e.g., `root`), explicitly define a secure `$PATH` in `/etc/profile`, `.bashrc`, or `.bash_profile`:
            
            ```bash
            export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ```
            
    3. **Monitor `$PATH` Changes:**
        - Detect runtime changes to `$PATH` using `auditd`:
            - Add a rule in `/etc/audit/rules.d/audit.rules`:
                
                ```bash
                -w /etc/environment -p wa -k path_changes
                -w ~/.bashrc -p wa -k path_changes
                ```
                
            - Restart `auditd`:
                
                ```bash
                systemctl restart auditd
                ```
                
    4. **Enforce Environment Restrictions:**
        - Use tools like `AppArmor` or `SELinux` to control environment variables for sensitive applications.

---

### **2. Privilege Escalation via SUID Bit**

### **What It Is:**

- The **SUID (Set User ID)** permission bit allows users to execute a file with the permissions of the file owner, typically root.
- Misconfigured SUID files can be exploited to gain elevated privileges.

### **How It Works:**

1. **Exploitable Binaries:**
    - SUID binaries with vulnerabilities or unintended functionality can be exploited.
    - Example with `cp`:
        
        ```bash
        cp /bin/bash /tmp/bash
        chmod +s /tmp/bash
        /tmp/bash -p  # Gains a root shell if owned by root with SUID
        ```
        
2. **Custom Scripts or Programs:**
    - If a custom binary/script is given the SUID bit and is poorly designed, attackers may exploit it to run arbitrary commands as root.
3. **Writable SUID Files:**
    - An attacker can modify the binary or overwrite it with malicious code if writable.
4. **Path Manipulation with SUID Executables:**
    - If a SUID program executes other programs without specifying absolute paths, an attacker can manipulate `$PATH` to substitute malicious binaries.

### **Detection and Prevention:**

- **Monitoring:**
    - Regularly scan for SUID binaries:
        
        ```bash
        find / -perm -4000 2>/dev/null
        find / -perms -u=s -type f 2>/dev/null
        ```
        
    - Use tools like `Lynis` or `chkrootkit` to check for potential SUID abuses.
- **Prevention:**

**1. Limit the Use of SUID to Essential Binaries Only**

### **Steps:**

1. **Identify Existing SUID Binaries:**
    - Use the following command to list all files with the SUID bit set:
        
        ```bash
        find / -perm -4000 2>/dev/null
        ```
        
2. **Evaluate Necessity:**
    - Check each binary’s purpose and determine if it is essential for system functionality.
    - Common SUID binaries that are typically required include:
        - `/usr/bin/sudo`
        - `/bin/passwd`
        - `/bin/mount` and `/bin/umount`
3. **Remove the SUID Bit if Not Needed:**
    - Use the `chmod` command to remove the SUID bit from non-essential binaries:
        
        ```bash
        chmod u-s /path/to/binary
        ```
        
4. **Test After Removal:**
    - Ensure the system continues to function as expected after removing the SUID bit.

---

**2. Regularly Audit and Verify the Integrity of SUID Binaries**

### **Steps:**

1. **Automate Regular SUID Audits:**
    - Create a cron job to periodically scan for SUID binaries:
        
        ```bash
        echo 'find / -perm -4000 2>/dev/null > /var/log/suid_audit.log' > /etc/cron.daily/suid_audit
        chmod +x /etc/cron.daily/suid_audit
        ```
        
2. **Compare Against a Baseline:**
    - Maintain a baseline list of approved SUID binaries and compare regularly:
        
        ```bash
        diff /var/log/suid_audit.log /etc/baseline_suid_binaries
        ```
        
3. **Verify Binary Integrity:**
    - Use tools like `sha256sum` to check if binaries have been tampered with:
        
        ```bash
        sha256sum /path/to/suid_binary
        ```
        

---

**3. Restrict Access to Directories Containing SUID Binaries**

### **Steps:**

1. **Restrict Write Access:**
    - Ensure directories containing SUID binaries (e.g., `/bin`, `/usr/bin`) are not writable by unauthorized users:
        
        ```bash
        chmod 755 /bin /usr/bin
        ```
        
2. **Implement Access Control Lists (ACLs):**
    - Use ACLs to further restrict access to sensitive directories:
        
        ```bash
        setfacl -m u:username:--- /bin
        ```
        
3. **Monitor Access:**
    - Use `auditd` to log and monitor access to directories containing SUID binaries:
        - Add rules in `/etc/audit/rules.d/audit.rules`:
            
            ```bash
            -w /bin -p x -k suid_bin_access
            ```
            

---

**4. Enforce File Integrity Monitoring**

### **Using `AIDE` (Advanced Intrusion Detection Environment):**

1. **Initialize the AIDE Database:**
    
    ```bash
    sudo aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    ```
    
2. **Configure Monitoring for SUID Binaries:**
    - Edit `/etc/aide/aide.conf` to include paths of SUID directories:
        
        ```
        /bin    p+i+n+u+g+s+b+m+c+acl+selinux+xattrs
        /usr/bin    p+i+n+u+g+s+b+m+c+acl+selinux+xattrs
        ```
        
3. **Run AIDE Scans:**
    
    ```bash
    sudo aide --check
    ```
    

---

### **Using `Tripwire`:**

1. **Initialize Configuration:**
    - Customize `/etc/tripwire/twpol.txt` to include SUID directories:
        
        ```
        /bin -> $(SEC_BIN),
        /usr/bin -> $(SEC_BIN),
        ```
        
2. **Create a Baseline:**
    
    ```bash
    sudo tripwire --init
    ```
    
3. **Run Regular Checks:**
    
    ```bash
    sudo tripwire --check
    ```
    

---

### **Additional Best Practices**

- **User Awareness:**
    - Educate users to avoid running untrusted binaries or scripts.
- **Logging and Alerts:**
    - Configure SIEM tools to generate alerts for unusual SUID binary usage.
- **Regular Updates:**
    - Apply system patches to address vulnerabilities in SUID binaries.

# **SOC Analyst’s Perspective**

1. **Indicators of Compromise (IOCs):**
    - `$PATH` variable modifications in logs or command histories.
    - Creation or execution of binaries in writable directories like `/tmp`.
    - Sudden or unauthorized execution of SUID binaries.
    - Changes to file permissions or ownership.
2. **Detection Tools:**
    - SIEM solutions for monitoring environment variables and commands.
    - Host-based Intrusion Detection Systems (HIDS) like `OSSEC`.
    - Log analysis with tools like `auditd` or `syslog`.
3. **Response Strategies:**
    - Terminate unauthorized processes exploiting PATH or SUID vulnerabilities.
    - Revert changes to `$PATH` and remove malicious binaries.
    - Investigate the source of the attack and ensure no backdoors are left.

---
