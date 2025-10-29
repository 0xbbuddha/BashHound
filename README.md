<div align="center">
  <img src="./img/bashhoundlogo.png" alt="BashHound Logo" width="200"/>
  
  # BashHound

  **Active Directory data collector for BloodHound written in Bash**

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![BashHound](https://img.shields.io/badge/Tool-BashHound-00E68E.svg)](https://github.com/0xbbuddha/BashHound)


  *Cross-platform • Fast • Stealth*

</div>

---

## Description

BashHound is a BloodHound data collector written in Bash, inspired by [RustHound](https://github.com/NH-RED-TEAM/RustHound) and [SharpHound](https://github.com/SpecterOps/SharpHound). It is designed to be compatible with Linux. It generates all the JSON files that can be analyzed by BloodHound.

BashHound was created as a technical challenge rather than for real-world use. Although the tool works, it is incomplete and not fully functional for advanced usage. Updates will be released regularly to improve it and make it increasingly functional.

---

## Usage

### Standart
```bash
bashhound -d <domain.local> -u <user> -p <password> -s <dc.domain.local> 
```

### Options
```bash
-c, --collection METHOD
Collection Methods:
    All       - Collects all data (default)
    DCOnly    - Collects only from the DC (no sessions)
    Session   - Collects only sessions
    Trusts    - Collects only trusts
    ACL       - Collects only ACLs
    Group     - Collects only group memberships

--zip-only      Deletes JSON files after creating the ZIP file
--port          PORT LDAP port (default: 389 for LDAP, 636 for LDAPS)
--ldaps         Use LDAPS (TLS) - equivalent to --port 636
--no-tls        Force LDAP without TLS even on port 636
```

---

## Disclaimer

<div style="border: 2px solid red; background-color: #ffe6e6; padding: 10px; border-radius: 8px;">
  All tests were carried out on the DarkZero machine on Hack The Box. “TODO” notes have been added to the code to make it compatible with any server.
</div>

---

## Related Projects

- [RustHound](https://github.com/NH-RED-TEAM/RustHound) - BloodHound collector written in Rust
- [SharpHound](https://github.com/SpecterOps/SharpHound) - Official BloodHound collector written in C#
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory relationship analysis tool

---

<div align="center">
  <sub>Made with Bash</sub>
</div>
